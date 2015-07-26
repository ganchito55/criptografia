# Introduccion
Programa cliente-servidor para el envio de datos cifrados a través de Internet. El programa es un ejemplo del uso de distintos sistemas criptografícos y cómo se podrían implementar. Consta de 3 opciones, cifrado de clave privada (AES), cifrado de clave publica (RSA) y el uso de una funcion hash (SHA2)

# Compilación
Para compilarlo se adjunta fichero Makefile, es necesario tener instalado la librería de desarrollo de ssl:
sudo apt-get install libssl-dev

# Modo de uso:

- 1 Compilar con el Makefile el proyecto (para ello nos metemos en la carpeta y ejecutamos el comando make)
- 2 Ejecutar el servidor
- 3 Ejecutar el cliente poniendo la IP del servidor (si lo estas ejecutando en el mismo ordenador 127.0.0.1) 
- 4 Probar el modo que quieras

# Agradecimientos y licencia
**Licencia**: Licenciado bajo la licencia MIT (puedes hacer cualquier cosa mientras haya atribución al creador)

**Agradecimientos**:
- Proyecto OpenSSL, se utiliza como base para este proyecto.

### Creado por Jorge Durán
