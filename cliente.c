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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netdb.h>

#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

#define PUERTO 5555
#define TAM_BUFFER 10000
#define AES_M 1
#define RSA_M 2
#define SHA_M 3
#define TAM_TEXTO 1000
#define TAM_TEXTO_CIFRADO 1500 //El texto cifrado puede ocupar más que en texto plano
#define RSA_LONG 4096
#define RSA_EXP 65537 //Es mucho mas seguro que exponentes pequeños como 3 y 17, y solo tiene 2 1s en binario


int menuAlgortimos(int s);
int clienteTCP(char *ip);
void funcionAES(int s);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
void handleErrors(void);
void funcionRSA(int s);
void funcionSHA(int s);

int main(int argc, char** argv) {

    int s; //Socket
    int retorno;
    if (argc < 2) {
        printf("El software debe ser llamado como cliente IPdelServidor: cliente 192.168.1.55");
        return 2;
    }
    s = clienteTCP(argv[1]);


    printf("\x1B[32m           +---------------------------------------+\n");
    printf("           |    ~·~ ClIENTE  CRIPTOGRAFICO   ~·    |\n");
    printf("           +---------------------------------------+\x1B[0m\n");
    retorno = menuAlgortimos(s);

    if (retorno == -1) {
        close(s);
        return 0;
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

    close(s);

    return 0;
}

/*
 Establecimiento de la conexión
 */
int clienteTCP(char *ip) {
    int s; /* connected socket descriptor */

    struct sockaddr_in servaddr_in; /* for server socket address */

    memset((char *) &servaddr_in, 0, sizeof (struct sockaddr_in));

    /* Set up the peer address to which we will connect. */
    servaddr_in.sin_family = AF_INET;
    servaddr_in.sin_addr.s_addr = inet_addr(ip);
    servaddr_in.sin_port = htons(PUERTO);

    /* Create the socket. */
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == -1) {
        perror("Cliente");
        fprintf(stderr, "unable to create socket\n");
        exit(1);
    }
    /* Try to connect to the remote server at the address
     * which was just built into peeraddr.
     */
    if (connect(s, (const struct sockaddr *) &servaddr_in, sizeof (struct sockaddr_in)) == -1) {
        perror("Cliente");
        fprintf(stderr, "unable to connect to remote\n");
        exit(1);
    }
    return s;
}

/*
 Selección del algoritmo a utilizar y verificacion del mismo
 */
int menuAlgortimos(int s) {
    int numL = -1, enviados;
    char buffer[TAM_BUFFER];

    do {
        printf("Introduce el valor correspondiente al sistema que quieras usar\n");
        printf("%d - AES\n", AES_M);
        printf("%d - RSA\n", RSA_M);
		printf("%d - SHA512\n",SHA_M);
        scanf("%d%*c", &numL);

        switch (numL) {
            case AES_M:
                strcpy(buffer, "AES");
                break;
            case RSA_M:
                strcpy(buffer, "RSA");
                break;
			case SHA_M:
				strcpy(buffer, "SHA");
				break;
            default:
                numL = -1;
        }
    } while (numL == -1);

    printf("Inicializando la conexion con el sistema criptografico %s", buffer);
    
    //Enviamos el algoritmo que queremos usar
    if (send(s, buffer, strlen(buffer), 0) != strlen(buffer)) fprintf(stderr, "Error al enviar el algoritmo");

    memset(buffer, 3, sizeof (buffer)); //Limpiamos el buffer
    enviados = recv(s, buffer, strlen(buffer), 0);
    if (enviados == -1) fprintf(stderr, "Error al recibir la confirmacion del algoritmo");
    else buffer[enviados] = '\0';

    printf(" <--- %s\n", buffer); //Imprimimos Ok o fallo
    
    return numL;
}

/*
 Ejemplo similar en https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
 */
void funcionAES(int s) {
    int i, enviados;
    unsigned char key[32]; //Clave
    unsigned char iv[16]; //Vector de inicializacion
    unsigned char ciphertext[TAM_TEXTO_CIFRADO];
    char texto[TAM_TEXTO];
    int ciphertextLen;
    FILE * f;

    //Genemos clave y vi aleatorios
    if (!RAND_bytes(key, sizeof (key))) {
        fprintf(stderr, "Error generando la clave");
        return;
    }
    if (!RAND_bytes(iv, sizeof (iv))) {
        fprintf(stderr, "Error generando el vector de inicializacion");
        return;
    }

    /*Cargamos las bibliotecas */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    printf("Generando clave:\nClave AES: ");
    for (i = 0; i < 32; i++) {
        printf("%x", key[i]);
    }
    printf("\n");

    printf("Introduzca el texto que quiera mandar cifrado\n");
    scanf("%[^\n]s%*c", texto);
    
    ciphertextLen = encrypt(texto, strlen(texto), key, iv, ciphertext); //Pasamos el texto y su tamaño, la clave, el iv y nos devuelve el texto cifrado y la longitud del mismo
    
    printf("Cifrado es:\n");
    BIO_dump_fp(stdout, (const char *) ciphertext, ciphertextLen);

    //Ahora enviamos el texto cifrado por el socket
    enviados = send(s, ciphertext, sizeof (char)*ciphertextLen, 0);
    if (enviados != ciphertextLen) fprintf(stderr, "Error al enviar el texto cifrado");
    puts("Informacion cifrada enviada");

    //Enviamos el vector de inicializacion por el socket
    //Se envia por esto: https://en.wikipedia.org/wiki/Initialization_vector
    //Mas informacion http://crypto.stackexchange.com/questions/732/why-use-an-initialization-vector-iv
    enviados = send(s, iv, sizeof (iv), 0);
    if (enviados != sizeof (iv)) fprintf(stderr, "Error al enviar el vector de inicializacion");
    puts("Vector de inicializacion enviado");

    f = fopen("clave.key", "wb");
    fwrite(key, sizeof (key), 1, f);
    fclose(f);
    puts("Archivo con la clave generada, envialo al receptor por un canal seguro");

}

/*
	Basado en https://shanetully.com/2012/04/simple-public-key-encryption-with-rsa-and-openssl/
*/
void funcionRSA(int s) {

	char *pt;
	int enviados;
	char buffer[10000],*textoClaro,*err;
	BIO *publica;
	size_t publicaLen;
    RSA *miClave = RSA_generate_key(RSA_LONG,RSA_EXP, NULL, NULL);
	
	err = malloc(sizeof(char)*1000);

	memset(buffer,0,sizeof(buffer));
	printf("Generado tu clave RSA de %d bits y exponente %d (publico) \n",RSA_LONG,RSA_EXP);

	
	pt = BN_bn2hex(miClave->d);
	printf("d exponente (privado) cumple d*e=1 mod (p-1)*(q-1)\n---------------------\n%s\n\n",pt);
	OPENSSL_free(pt);

	pt = BN_bn2hex(miClave->p);	
	printf("p primer factor primo de la clave (secreto)\n---------------------\n%s\n\n",pt);
	OPENSSL_free(pt);
	
	pt = BN_bn2hex(miClave->q);
	printf("q segundo factor primo de la clave (secreto)\n---------------------\n%s\n\n",pt);
	OPENSSL_free(pt);

	pt = BN_bn2hex(miClave->n);
	printf("n modulo con el que trabajamos = p*q (publico)\n--------------------\n%s\n\n",pt);
	OPENSSL_free(pt);

	//Utilizancion de las funciones de OpenSSL para generar un string con la clave publica y asi poder enviarlo por el socket
	publica = BIO_new(BIO_s_mem());	
	PEM_write_bio_RSAPublicKey(publica,miClave);
	publicaLen = BIO_pending(publica);
	BIO_read(publica,buffer,publicaLen);	

	puts("Ahora enviamos n y e que son los datos publicos al servidor");
	if((enviados=send(s,buffer,publicaLen,0))!=publicaLen) fprintf(stderr,"Error en RSA al enviar n");


	puts("Esperando la recepcion del texto cifrado");
	memset(buffer,3,sizeof(buffer));
	enviados = 0;
	enviados = recv(s,buffer,sizeof(buffer),0);
	if(enviados==-1) fprintf(stderr,"Error al recibir el texto cifrado");

	BIO_dump_fp(stdout, (const char *) buffer, enviados);

	//Desciframos lo que recibimos con nuestra clave privada
	textoClaro = malloc((enviados+1)*sizeof(char));
if(RSA_private_decrypt(enviados, (unsigned char*)buffer, (unsigned char*)textoClaro, miClave, RSA_PKCS1_OAEP_PADDING) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error decrypting message: %s\n", err);
	}
	printf("\nEl texto descifrado es:\n%s\n",textoClaro);	

	free(textoClaro);
	free(err);
	RSA_free(miClave);	
}

void funcionSHA(int s){
	char texto[1000];
	unsigned char hash[512/8];
	int numChar;

	memset(texto,0,sizeof(texto));
	fflush(stdin);
	puts("Introduce tu texto");
	scanf("%[^\n]s%*c",texto);

	SHA512((unsigned char*)texto,strlen(texto),hash);

	printf("Hash:\n");
	BIO_dump_fp(stdout, (const char *) hash, 512/8);	

	if((numChar=send(s,texto,strlen(texto),0))!=strlen(texto)) fprintf(stderr,"Error al enviar el texto");
	sleep(1);
	if((numChar=send(s,hash,512/8,0))!=(512/8)) fprintf(stderr,"Error al enviar el hash");	

}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
        unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

