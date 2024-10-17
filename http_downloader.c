#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

struct DownloadInfo {
    struct addrinfo server_address_info;
    char ip_address[INET6_ADDRSTRLEN];
    char output_filename[200];
    char file_path[200];
    int range_start;
    int range_end;
    int range;
};


void verifyInputs(char *https_url, int num_tcp_connections, char *destination_file) {
    if (https_url == NULL) {
        fprintf(stderr, "URL must be specified.\n");
        exit(EXIT_FAILURE);
    }

    if (num_tcp_connections <= 0) {
        fprintf(stderr, "Number of parts must be specified and must be an integer greater than 0\n");
        exit(EXIT_FAILURE);
    }

    if (destination_file == NULL) {
        fprintf(stderr, "Output file must be specified.\n");
        exit(EXIT_FAILURE);
    }
}


void parseHostNameAndFilePath(struct DownloadInfo *downloadinfo, const char *url) {
    const char *hostname_start = strstr(url, "://");
    if (hostname_start == NULL) {
        printf("Invalid URL format\n");
        exit(EXIT_FAILURE);
    }
    hostname_start += 3;

    const char *path_start = strchr(hostname_start, '/');
    if (path_start == NULL) {
        printf("Invalid URL format, URL must contain path to the object to be downloaded\n");
        exit(EXIT_FAILURE);
    }

    strcpy(downloadinfo->file_path, path_start);

    size_t host_len = path_start - hostname_start;
    strncpy(downloadinfo->ip_address, hostname_start, host_len);
    downloadinfo->ip_address[host_len] = '\0';
}


void resolveIpAdress(struct DownloadInfo *downloadinfo, const char *url) {
    char duplicate_url[200];
    strcpy(duplicate_url, url);
    
    char *ptr = strtok(duplicate_url, "//");
    int i =0;
    while(i<1)
    {   
        ptr = strtok(NULL, "//");
        i +=1;
    }

    struct addrinfo clues, *response;

    memset(&clues, 0, sizeof(clues));
    clues.ai_family = AF_INET;
    clues.ai_socktype = SOCK_STREAM;

    int response_status = getaddrinfo(downloadinfo->ip_address, "443", &clues, &response);
    if (response_status != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(response_status));
        exit(EXIT_FAILURE);
    }

    downloadinfo->server_address_info = *response;

    if (response->ai_family == AF_INET) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)response->ai_addr;
        inet_ntop(AF_INET, &(ipv4->sin_addr), downloadinfo->ip_address, sizeof(downloadinfo->ip_address));
    }
    else {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)response->ai_addr;
        inet_ntop(AF_INET6, &(ipv6->sin6_addr), downloadinfo->ip_address, sizeof(downloadinfo->ip_address));
    }
}


BIO *create_ssl_connection(struct DownloadInfo *downloadinfo) {
    SSL_CTX *ssl_ctx = SSL_CTX_new(SSLv23_client_method());

    if ( ssl_ctx == NULL ) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    BIO *bio = BIO_new_ssl_connect(ssl_ctx);

    if (bio == NULL) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    BIO_get_ssl(bio, &ssl_ctx);
    BIO_set_conn_hostname(bio, downloadinfo->ip_address);
    BIO_set_conn_port(bio, "443");

    if (BIO_do_connect(bio) <= 0) {
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ssl_ctx);

        return NULL;
    }

    return bio;
}


int requestFileSize(struct DownloadInfo *downloadinfo) {
    BIO *bio = create_ssl_connection(downloadinfo);

    if (bio == NULL) {
        return -1;
    }

    char query[1024];
    sprintf(query, "HEAD %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", downloadinfo->file_path, downloadinfo->ip_address);

    BIO_write(bio, query, strlen(query));

    char response[2000];
    BIO_read(bio, response, sizeof(response));

    char *match = strstr(response, "Content-Length:");

    int file_size = -1;
    if (match != NULL) {
        match = strtok(match, "\r\n");
        char *token = strtok(match, " :");

        while (token != NULL) {
            token = strtok(NULL, " ");

            if (token != NULL) {
                file_size = atoi(token);
                break;
            }
        }

        BIO_free_all(bio);

        return file_size;
    }

    BIO_free_all(bio);
    return -1;
}


void *create_tls_session(void *segment_info) {
    struct DownloadInfo *downloadinfo = segment_info;
    char *ip = downloadinfo->ip_address;
    char *output = downloadinfo->output_filename;
    char *file_path = downloadinfo->file_path;
    int r_start = downloadinfo->range_start;
    int r_end = downloadinfo->range_end;
    int r = downloadinfo->range;

    BIO *bio = create_ssl_connection(downloadinfo);
    
    if (bio == NULL) {
        printf("Failed to establish SSL connection\n");
        return NULL;
    }

    char name[100];
    sprintf(name, "part_%d", r);
    FILE *file = fopen(name, "ab");

    if (file == NULL) {
        printf("File could not be opened\n");
        BIO_free_all(bio);
        return NULL;
    }

    char query[1024];
    sprintf(query, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) (Macintosh; Intel Mac OS X 10_14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\r\nReferer: %s\r\nRange: bytes=%d-%d\r\nConnection: close\r\n\r\n",
            file_path, ip, ip, r_start, r_end);

    BIO_write(bio, query, strlen(query));

    char response[1290000];
    int numOfBytes;
    while ((numOfBytes = BIO_read(bio, response, sizeof(response))) > 0) {

        if (numOfBytes == -1) {
            printf("Error reading from SSL connection\n");
            break;
        }

        char *b = strstr(response, "\r\n\r\n");
        int offSet;

        if (b != NULL) {
            offSet = b - response + 4;
        }
        else {
            offSet = 0;
        }

        if ( (offSet < r_end - r_start) &&
             (offSet > 0) ) {
                char *t = response + offSet;
        }
        else {
            fwrite(response, numOfBytes, 1, file);
        }
    }

    fclose(file);
    BIO_free_all(bio);
}


int main(int argc, char **argv) {

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    char *url = NULL;
    int num_parts = -1;
    char *output_file = NULL;

    int option;
    while ((option = getopt(argc, argv, "u:n:o:")) != -1) {
        switch (option) {
            case 'u':
                url = optarg;
                break;
            case 'n':
                num_parts = atoi(optarg);
                break;
            case 'o':
                output_file = optarg;
                break;
            default:
                fprintf (stderr, "Usage of Program: %s -u URL -n NUM_PARTS -o OUTPUT_FILE\nURL: HTTP(S) link of the file.\nNUM_PARTS: Number of connections established to download the file.\nOUTPUT_FILE: Name of the ouput file.\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    verifyInputs(url, num_parts, output_file);

    struct DownloadInfo *info = malloc( sizeof(struct DownloadInfo) );
    strcpy(info->output_filename, output_file);

    parseHostNameAndFilePath(info, url);
    printf("Host: %s\n", info->ip_address);
    printf("Path: %s\n", info->file_path);

    resolveIpAdress(info, url);
    printf("Resolved IP Address: %s\n", info->ip_address);

    int file_size = requestFileSize(info);
    printf("The file is of size %d bytes.\n", file_size);


    int part_size;
    part_size = file_size/num_parts;
    struct DownloadInfo *segment[num_parts];

    for( int itr = 0; itr < num_parts; itr++ ){

        segment[itr] = malloc( sizeof(struct DownloadInfo) );
        segment[itr]->server_address_info = info->server_address_info;

        strcpy( segment[itr]->output_filename, output_file );
        strcpy( segment[itr]->ip_address, info->ip_address );
        strcpy( segment[itr]->file_path, info->file_path );

        segment[itr]->range = itr + 1;
        segment[itr]->range_start = itr * part_size;

        if ( itr != num_parts - 1 ) {
            segment[itr]->range_end = ((itr + 1) * part_size) - 1;
        }
        else {
            segment[itr]->range_end = file_size;
        }
    }

    int thread_status;
    pthread_t id[num_parts];

    for(int p = 0; p < num_parts; p++ ) {
        thread_status = pthread_create(&id[p], NULL, create_tls_session, segment[p]);

        if (thread_status!=0) {
            printf("Error:unable to create thread, %d\n", thread_status);
            exit(-1);
        }
    }

    FILE *result_file_ptr = NULL;
    result_file_ptr = fopen(output_file, "ab");

    int ra;

    printf("Stiching the parts into single output file.\n");

    for(int k = 0 ; k < num_parts; ++k){  

        if (k==num_parts-1) {
            ra = segment[k]->range_end-segment[k]->range_start;
        }
        else {
            ra = (segment[k]->range_end-segment[k]->range_start)+1;
        }

        void* status;
        int t = pthread_join(id[k], &status);

        if (t != 0) {
            printf("Execution of thread failed, %d\n", k);
            exit(-1);
        }

        FILE *fp = NULL;
        char filename[100], data[ra];

        sprintf(filename, "part_%d", (k+1));
        fp = fopen(filename, "rb");

        if ( fp == NULL ) {
                 printf( "Could not open file %s", filename ) ;
        }

        fread(data,ra, 1, fp);
        fwrite(data, ra, 1, result_file_ptr);
         
        fclose(fp) ;
    }
    fclose(result_file_ptr);

    for (int itr = 0; itr < num_parts; itr++) {
        free(segment[itr]);
    }
    free(info);

    printf("Successfully Done.\n");
   
    return 0;
}