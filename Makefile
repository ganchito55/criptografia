all: cliente servidor
	@echo "LISTO"
cliente: cliente.c
	gcc cliente.c -o cliente -lcrypto
servidor: servidor.c
	gcc servidor.c -o servidor -lcrypto
clean:
	rm servidor cliente
