/* Optional Mbed TLS 3.6 memory transport. No Python or socket ownership. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/ssl.h>
#include <mbedtls/version.h>

#if MBEDTLS_VERSION_MAJOR != 3 || MBEDTLS_VERSION_MINOR != 6
#error "This backend requires Mbed TLS 3.6 headers and libraries"
#endif

#define CAPACITY 65535
typedef struct {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context random;
    unsigned char incoming[CAPACITY], outgoing[CAPACITY];
    size_t incoming_size, outgoing_size;
    double timer_start;
    uint32_t intermediate_ms, final_ms;
} lt_connection;

static double monotonic_seconds(void) {
    struct timespec stamp;
    clock_gettime(CLOCK_MONOTONIC, &stamp);
    return stamp.tv_sec + stamp.tv_nsec / 1e9;
}

static void set_timer(void *context, uint32_t intermediate, uint32_t final) {
    lt_connection *connection = context;
    connection->timer_start = monotonic_seconds();
    connection->intermediate_ms = intermediate;
    connection->final_ms = final;
}

static int get_timer(void *context) {
    lt_connection *connection = context;
    if (!connection->final_ms) return -1;
    double elapsed = 1000 * (monotonic_seconds() - connection->timer_start);
    if (elapsed >= connection->final_ms) return 2;
    return elapsed >= connection->intermediate_ms ? 1 : 0;
}

static int send_record(void *context, const unsigned char *data, size_t size) {
    lt_connection *connection = context;
    if (size > CAPACITY - connection->outgoing_size)
        return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    memcpy(connection->outgoing + connection->outgoing_size, data, size);
    connection->outgoing_size += size;
    return (int)size;
}

static int receive_record(void *context, unsigned char *data, size_t capacity) {
    lt_connection *connection = context;
    if (!connection->incoming_size) return MBEDTLS_ERR_SSL_WANT_READ;
    size_t size = connection->incoming_size;
    connection->incoming_size = 0;
    if (size > capacity) return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    memcpy(data, connection->incoming, size);
    return (int)size;
}

int lt_api_version(void) {
    return (mbedtls_version_get_number() >> 16) == (MBEDTLS_VERSION_NUMBER >> 16) ? 1 : 0;
}

void lt_free(lt_connection *connection) {
    if (!connection) return;
    mbedtls_ssl_free(&connection->ssl);
    mbedtls_ssl_config_free(&connection->config);
    mbedtls_ctr_drbg_free(&connection->random);
    mbedtls_entropy_free(&connection->entropy);
    mbedtls_platform_zeroize(connection, sizeof(*connection));
    free(connection);
}

lt_connection *lt_new(const unsigned char *identity, size_t identity_size,
                      const unsigned char *key, size_t key_size,
                      unsigned short mtu, int *error) {
    *error = MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    if (!identity || !key || identity_size != 16 || (key_size != 16 && key_size != 32))
        return NULL;
    lt_connection *connection = calloc(1, sizeof(*connection));
    if (!connection) { *error = MBEDTLS_ERR_SSL_ALLOC_FAILED; return NULL; }
    mbedtls_ssl_init(&connection->ssl);
    mbedtls_ssl_config_init(&connection->config);
    mbedtls_entropy_init(&connection->entropy);
    mbedtls_ctr_drbg_init(&connection->random);
    static const int ciphers[] = {MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, 0};
#define CHECK(call) do { *error = (call); if (*error != 0) goto failed; } while (0)
    CHECK(mbedtls_ctr_drbg_seed(&connection->random, mbedtls_entropy_func,
                                &connection->entropy, NULL, 0));
    CHECK(mbedtls_ssl_config_defaults(&connection->config, MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT));
    mbedtls_ssl_conf_rng(&connection->config, mbedtls_ctr_drbg_random, &connection->random);
    mbedtls_ssl_conf_min_tls_version(&connection->config, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&connection->config, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_ciphersuites(&connection->config, ciphers);
    CHECK(mbedtls_ssl_conf_psk(&connection->config, key, key_size, identity, identity_size));
    CHECK(mbedtls_ssl_setup(&connection->ssl, &connection->config));
    mbedtls_ssl_set_mtu(&connection->ssl, mtu);
    mbedtls_ssl_set_bio(&connection->ssl, connection, send_record, receive_record, NULL);
    mbedtls_ssl_set_timer_cb(&connection->ssl, connection, set_timer, get_timer);
    return connection;
failed:
    lt_free(connection);
    return NULL;
#undef CHECK
}

int lt_handshake(lt_connection *connection) { return mbedtls_ssl_handshake(&connection->ssl); }
int lt_shutdown(lt_connection *connection) { return mbedtls_ssl_close_notify(&connection->ssl); }
int lt_write(lt_connection *connection, const unsigned char *data, size_t size) {
    return mbedtls_ssl_write(&connection->ssl, data, size);
}
int lt_read(lt_connection *connection, unsigned char *data, size_t size) {
    return mbedtls_ssl_read(&connection->ssl, data, size);
}
int lt_feed(lt_connection *connection, const unsigned char *data, size_t size) {
    if (connection->incoming_size || size > CAPACITY) return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    memcpy(connection->incoming, data, size);
    connection->incoming_size = size;
    return (int)size;
}
int lt_drain(lt_connection *connection, unsigned char *data, size_t capacity) {
    size_t size = connection->outgoing_size;
    if (!size) return MBEDTLS_ERR_SSL_WANT_READ;
    if (size > capacity) return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    memcpy(data, connection->outgoing, size);
    connection->outgoing_size = 0;
    return (int)size;
}
double lt_timeout(lt_connection *connection) {
    if (!connection->final_ms) return -1;
    double remaining = connection->final_ms / 1000.0 - (monotonic_seconds() - connection->timer_start);
    return remaining > 0 ? remaining : 0;
}
