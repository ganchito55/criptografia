/*
Creado por Jorge Duran (ganchito55@gmail.com)
The MIT License (MIT)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>

#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>

#define PORT 5555
#define AES_M 1
#define RSA_M 2
#define SHA_M 3
#define TAM_TEXTO 1000
#define TAM_TEXTO_CIFRADO 1500 //El texto cifrado puede ocupar más que en texto plano



int FIN = 0;

void serverTCP(int s, struct sockaddr_in clientaddr_in);
int leerAlgoritmo(int s);
void funcionAES(int s);
void funcionRSA(int s);
void funcionSHA(int s);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);
void handleErrors(void);

void finalizar() {
    FIN = 1;
}

int main(int argc, char * argv[]) {

    int s_Handler; /*connected socket descriptor*/
    int ls_Handler; /* listen socket descriptor */

    struct sockaddr_in myAddr; /* local socket address */
    struct sockaddr_in clientaddr_in; /* client socket address */
    struct sigaction vec;

    struct sigaction sa = {.sa_handler = SIG_IGN}; /* used to ignore SIGCHLD */

    int FIN = 0;
    int numfds;
    int addrlen;
    addrlen = sizeof (struct sockaddr_in);
    fd_set readmask;

    /* clear address structure */
    memset((char *) &myAddr, 0, sizeof (struct sockaddr_in));
    memset((char *) &clientaddr_in, 0, sizeof (struct sockaddr_in));

    /* Set up address structure for the listen socket. */
    myAddr.sin_family = AF_INET;
    /* The server should listen on the wildcard address,
     * rather than its own internet address.  This is
     * generally good practice for servers, because on
     * systems which are connected to more than one
     * network at once will be able to have one server
     * listening on all networks at once.  Even when the
     * host is connected to only one network, this is good
     * practice, because it makes the server program more
     * portable.
     */
    myAddr.sin_addr.s_addr = INADDR_ANY;
    myAddr.sin_port = htons(PORT);

    /* Create the listen socket. */
    ls_Handler = socket(AF_INET, SOCK_STREAM, 0);
    if (ls_Handler == -1) {
        perror(argv[0]);
        fprintf(stderr, "%s: unable to create socket TCP\n", argv[0]);
        exit(1);
    }
    /* Bind the listen address to the socket. */
    if (bind(ls_Handler, (const struct sockaddr *) &myAddr, sizeof (struct sockaddr_in)) == -1) {
        perror(argv[0]);
        fprintf(stderr, "%s: unable to bind address TCP\n", argv[0]);
        exit(1);
    }
    /* Initiate the listen on the socket so remote users
     * can connect.  The listen backlog is set to 5, which
     * is the largest currently supported.
     */
    if (listen(ls_Handler, 5) == -1) {
        perror(argv[0]);
        fprintf(stderr, "%s: unable to listen on socket\n", argv[0]);
        exit(1);
    }


    /* Set SIGCLD to SIG_IGN, in order to prevent
     * the accumulation of zombies as each child
     * terminates.  This means the daemon does not
     * have to make wait calls to clean them up.
     */
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror(" sigaction(SIGCHLD)");
        fprintf(stderr, "%s: unable to register the SIGCHLD signal\n", argv[0]);
        exit(1);
    }

    /* Register SIGTERM  */
    vec.sa_handler = (void *) finalizar;
    vec.sa_flags = 0;
    if (sigaction(SIGTERM, &vec, (struct sigaction *) 0) == -1) {
        perror(" sigaction(SIGTERM)");
        fprintf(stderr, "%s: unable to register the SIGTERM signal\n", argv[0]);
        exit(1);
    }


        FD_ZERO(&readmask);
        FD_SET(ls_Handler, &readmask);

        if ((numfds = select(getdtablesize(), &readmask, (fd_set *) 0, (fd_set *) 0, NULL)) < 0) {
            if (errno == EINTR) {
                FIN = 1;
                perror("\nselect failed\n ");
            }
        } else {
            if (FD_ISSET(ls_Handler, &readmask)) {
                /* Note that addrlen is passed as a pointer
                 * so that the accept call can return the
                 * size of the returned address.
                 */
                /* This call will block until a new
                 * connection arrives.  Then, it will
                 * return the address of the connecting
                 * peer, and a new socket descriptor, s,
                 * for that connection.
                 */
                s_Handler = accept(ls_Handler, (struct sockaddr *) &clientaddr_in, &addrlen);
                if (s_Handler == -1) exit(1);

                close(ls_Handler); /* Close the listen socket inherited from the daemon. */
                serverTCP(s_Handler, clientaddr_in);            
        }
    }
    close(s_Handler);
	return 0;
}

void serverTCP(int s, struct sockaddr_in clientaddr_in) {
    int retorno;

    printf("\x1B[32m           +---------------------------------------+\n");
    printf("           |    ~·~ SERVIDOR CRIPTOGRAFICO   ~·    |\n");
    printf("           +---------------------------------------+\x1B[0m\n");
    retorno = leerAlgoritmo(s);
    if (retorno == -1) { //No se sabemos usar ese sistema
        return;
    }
    switch (retorno) {
        case AES_M:
            funcionAES(s);
            break;
		case RSA_M:
			funcionRSA(s);
			break;
		case SHA_M:
			funcionSHA(s);
			break;
    }
}

/*
El primer paso del protocolo es leer el algoritmo de cifrado de la comunicación
Mandamos OK si sabemos usarlo FALLO si no lo conocemos
 */
int leerAlgoritmo(int s) {
    int caracteresLeidos;
    char buffer[65536];


    caracteresLeidos = recv(s, buffer, 65536, 0); //Leemos el algoritmo

    if (caracteresLeidos == -1) exit(1);
    else buffer[caracteresLeidos] = '\0';

    printf("El cliente quiere usar el algortimo %s ", buffer);
    strcmp("RSA", buffer);
    if (strcmp("RSA", buffer) == 0) {
        printf(" ---> ACEPTADO\n");
        if (send(s, "OK", strlen("OK"), 0) != strlen("OK")) fprintf(stderr, "Error al enviar OK al aceptar el mensaje");
        return RSA_M;
    }
    if (strcmp("AES", buffer) == 0) {
        printf(" ---> ACEPTADO\n");
        if (send(s, "OK", strlen("OK"), 0) != strlen("OK")) fprintf(stderr, "Error al enviar OK al aceptar el mensaje");
        return AES_M;
    }
	if (strcmp("SHA", buffer) == 0) {
        printf(" ---> ACEPTADO\n");
        if (send(s, "OK", strlen("OK"), 0) != strlen("OK")) fprintf(stderr, "Error al enviar OK al aceptar el mensaje");
        return SHA_M;
    }
	

    printf(" ---> NO SOPORTADO\n");
    if (send(s, "FALLO", strlen("FALLO"), 0) != strlen("FALLO")) fprintf(stderr, "Error al enviar FALLO por no soportar el sistema");

    return -1;
}

void funcionAES(int s) {
    int leidos, tam_decrypt, viLeidos;
    char textoCifrado[TAM_TEXTO_CIFRADO], textoClaro[TAM_TEXTO];
    unsigned char key[32];
    unsigned char vi[16]; //Vector de inicializacion
    FILE *f;
    int i;


    memset(textoCifrado, 0, sizeof (textoCifrado));
    memset(textoClaro, 1, sizeof (textoClaro));
    leidos = recv(s, textoCifrado, sizeof (textoCifrado), 0);
    if (leidos == -1) fprintf(stderr, "Error al leer el texto cifrado");

    viLeidos = recv(s, vi, sizeof (vi), 0);
    if (viLeidos == -1) fprintf(stderr, "Error al leer el Vector de inicializacion");

    printf("Recibido: \n");
    BIO_dump_fp(stdout, (const char *) textoCifrado, leidos);

    puts("Ponga el archivo clave.key en la misma carpeta que este programa y presione enter");
    scanf("%*c");

    //Cargamos la clave
    if ((f = fopen("clave.key", "rb")) == NULL) {
        fprintf(stderr, "Error no se encuentra el archivo con la clave \"clave.key\" ");
    }
    fread(key, sizeof (key), 1, f);
    fclose(f);

    printf("Clave AES: ");
    for (i = 0; i < 32; i++) {
        printf("%x", key[i]);
    }
    printf("\n");

    tam_decrypt = decrypt(textoCifrado, leidos, key, vi, textoClaro);
    textoClaro[tam_decrypt] = '\0';
    printf("Descifrado:\n%s\n", textoClaro);

}


void funcionRSA(int s){
	int leidos,textoCifradoLen;
	char texto[10000],RSA_clave[12000], RSA_e[100], *textoCifrado = NULL, *err;
	BIGNUM *cifrado;
	RSA *datosCliente = RSA_new();

	memset(RSA_clave,0,sizeof(RSA_clave)); //Limpiar los buffer
	memset(RSA_e,0,sizeof(RSA_e));
	err = malloc(sizeof(char)*100);

	leidos = recv(s,RSA_clave,sizeof(RSA_clave),0);
	if(leidos == -1) fprintf(stderr,"Error al recibir la clave RSA");

	BIO *clave = BIO_new(BIO_s_mem());	
	BIO_write(clave,RSA_clave,leidos);
	datosCliente = PEM_read_bio_RSAPublicKey(clave,NULL,NULL,NULL);
	
	//Cogemos el texto a cifrar
	printf("Introduzca el texto que quiera mandar cifrado\n");
    scanf("%[^\n]s%*c", texto);

	//puts("Ahora hacemos texto^e mod n");
	textoCifrado = malloc(RSA_size(datosCliente));
	if((textoCifradoLen = RSA_public_encrypt(strlen(texto)+1, (unsigned char*)texto,
   (unsigned char*)textoCifrado, datosCliente, RSA_PKCS1_OAEP_PADDING)) == -1) {
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    fprintf(stderr, "Error cifrado el mensaje: %s\n", err);
	}

	puts("Texto cifrado:");
	BIO_dump_fp(stdout, (const char *) textoCifrado, textoCifradoLen);

	puts("Lo enviamos al cliente");
	//Lo enviamos al cliente
	if((leidos=send(s,textoCifrado,sizeof(char)*textoCifradoLen,0))!=sizeof(char)*textoCifradoLen) fprintf(stderr,"Error al enviar el texto cifrado");
	
	//Libero la memoria del texto cifrado
	free(textoCifrado);
	free(err);
	RSA_free(datosCliente);	

}

void funcionSHA(int s) {
	int numChar;
	char texto[1200],hash[(512/8)+1],hashR[(512/8)+1];

	memset(texto,0,sizeof(texto));
	memset(hash,0,sizeof(hash));
	memset(hashR,0,sizeof(hashR));

	numChar = recv(s,texto,sizeof(texto),0);
	if(numChar==-1) fprintf(stderr,"Error al recibir el texto");
	
	printf("Texto recibido:\n%s\n",texto);

	numChar = recv(s,hashR,512/8,0);
	if(numChar == -1) fprintf(stderr,"Error al recibir el hash");
	
	SHA512((unsigned char*)texto,strlen(texto),hash);
	printf("Hash:\n");
	BIO_dump_fp(stdout, (const char *) hash, 512/8);

	if(strcmp(hash,hashR)==0){
		printf("Los hash coinciden, texto recibido sin modificaciones\n");
	}
	else{
		printf("Los hash no coinciden, hay fallos \n\x1B[31mHash recibido:\n");
		BIO_dump_fp(stdout, (const char *) hashR, 512/8);
		printf("\x1B[0m");

	}

	printf("Ahora cambio la primera letra por ~\n");
	texto[0]='~';
	SHA512((unsigned char*)texto,strlen(texto),hash);
	printf("\x1B[34mHash nuevo:\n");
	BIO_dump_fp(stdout, (const char *) hash, 512/8);
	
	printf("\n\n\x1B[33mHash antiguo:\n");
	BIO_dump_fp(stdout, (const char *) hashR, 512/8);
	printf("\x1B[0m");
	

}


int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
        unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}
