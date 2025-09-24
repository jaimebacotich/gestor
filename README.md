
# Gestor de Contraseñas Seguro

Este es un gestor de contraseñas de consola desarrollado en Python como proyecto final. La aplicación permite a los usuarios almacenar, listar, buscar y eliminar credenciales de forma segura, utilizando criptografía para proteger los datos sensibles.

## Características

- **Autenticación con Contraseña Maestra:** Acceso seguro a la aplicación.
- **Cifrado Fuerte:** Los datos se almacenan en un archivo cifrado con el algoritmo Fernet (AES-128 en modo CBC con HMAC).
- **Derivación de Clave Segura:** La clave de cifrado se deriva de la contraseña maestra usando PBKDF2 con SHA-256, lo que previene ataques de diccionario y arcoíris.
- **Gestión de Credenciales:**
  - Agregar nuevas contraseñas.
  - Listar todas las contraseñas guardadas.
  - Buscar un servicio específico.
  - Eliminar una contraseña.
- **Cambio de Contraseña Maestra:** Permite cambiar la clave principal, re-cifrando todos los datos de forma segura.
- **Interfaz de Consola:** Interfaz de usuario limpia y fácil de usar en la terminal.

## Tecnologías Utilizadas

- **Lenguaje:** Python 3
- **Librería de Criptografía:** `cryptography`

## Puesta en Marcha

Sigue estos pasos para ejecutar el gestor en tu máquina local.

### Requisitos

- Python 3.6 o superior
- pip (el gestor de paquetes de Python)

### Instalación y Ejecución

1.  **Clona el repositorio:**
    ```bash
    git clone <URL_DEL_REPOSITORIO_EN_GITHUB>
    ```

2.  **Navega al directorio del proyecto:**
    ```bash
    cd gestor
    ```

3.  **Instala las dependencias necesarias:**
    ```bash
    pip install cryptography
    ```

4.  **Ejecuta la aplicación:**
    ```bash
    python gestor.py
    ```

## Funcionamiento

- **Primer Uso:** La primera vez que ejecutes el programa, te pedirá que crees una **Contraseña Maestra**. Esta contraseña es crucial y no se puede recuperar.
- **Inicios Posteriores:** En los siguientes usos, el programa te pedirá la Contraseña Maestra para iniciar sesión y descifrar tus datos.
- **Archivos Generados:** La aplicación creará 3 archivos en su directorio:
  - `master.hash`: Contiene el hash de tu contraseña maestra para verificación.
  - `salt.key`: Una clave aleatoria usada para fortalecer el cifrado.
  - `contrasenas.json.cifrado`: El archivo con tus datos, completamente cifrado.
