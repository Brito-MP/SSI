#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int parse_port(const char *text)
{
    char *end = NULL;
    long value = strtol(text, &end, 10);

    if (*text == '\0' || *end != '\0' || value < 1 || value > 65535) {
        return -1;
    }

    return (int)value;
}

int main(int argc, char **argv)
{
    struct sockaddr_in address;
    int enable = 1;
    int port;
    int sockfd;

    if (argc != 2) {
        fprintf(stderr, "Uso: %s <porta>\n", argv[0]);
        return EXIT_FAILURE;
    }

    port = parse_port(argv[1]);
    if (port < 0) {
        fprintf(stderr, "Porta invalida\n");
        return EXIT_FAILURE;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0) {
        perror("setsockopt");
        close(sockfd);
        return EXIT_FAILURE;
    }

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons((uint16_t)port);

    if (bind(sockfd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        fprintf(stderr, "bind(%d): %s\n", port, strerror(errno));
        close(sockfd);
        return EXIT_FAILURE;
    }

    printf("Bind TCP efetuado na porta %d\n", port);
    close(sockfd);
    return EXIT_SUCCESS;
}
