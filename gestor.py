# -*- coding: utf-8 -*-
import os
import hashlib
import getpass
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ARCHIVO_HASH_MAESTRA = "master.hash"
ARCHIVO_CONTRASENAS = "contrasenas.json.cifrado"
ARCHIVO_SALT = "salt.key"

def derivar_clave(contrasena_maestra: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(contrasena_maestra.encode()))

def generar_y_guardar_salt():
    salt = os.urandom(16)
    with open(ARCHIVO_SALT, "wb") as f:
        f.write(salt)
    return salt

def cargar_salt():
    with open(ARCHIVO_SALT, "rb") as f:
        return f.read()

def cargar_datos(clave: bytes) -> dict:
    if not os.path.exists(ARCHIVO_CONTRASENAS):
        return {}
    
    with open(ARCHIVO_CONTRASENAS, "rb") as f:
        datos_cifrados = f.read()
    
    fernet = Fernet(clave)
    datos_descifrados = fernet.decrypt(datos_cifrados)
    return json.loads(datos_descifrados)

def guardar_datos(datos: dict, clave: bytes):
    fernet = Fernet(clave)
    datos_json = json.dumps(datos).encode()
    datos_cifrados = fernet.encrypt(datos_json)
    
    with open(ARCHIVO_CONTRASENAS, "w+b") as f:
        f.write(datos_cifrados)

def iniciar_sesion() -> bytes | None:
    print("--- INICIAR SESIÓN ---")
    contrasena_maestra = getpass.getpass("Ingresa tu Contraseña Maestra: ")
    
    with open(ARCHIVO_HASH_MAESTRA, "r") as f:
        hash_guardado = f.read()
        
    if hashlib.sha256(contrasena_maestra.encode()).hexdigest() == hash_guardado:
        print("¡Inicio de sesión exitoso!\n")
        salt = cargar_salt()
        clave = derivar_clave(contrasena_maestra, salt)
        return clave
    else:
        print("Contraseña Maestra incorrecta.\n")
        return None

def configurar_contrasena_maestra():
    print("--- CONFIGURACIÓN INICIAL ---")
    print("Parece que es la primera vez que usas el gestor.")
    print("Por favor, crea tu Contraseña Maestra. La necesitarás cada vez que uses el programa.")
    
    while True:
        contrasena_maestra = getpass.getpass("Crea tu Contraseña Maestra: ")
        confirmacion_contrasena = getpass.getpass("Confirma tu Contraseña Maestra: ")
        
        if contrasena_maestra == confirmacion_contrasena and contrasena_maestra:
            hash_maestra = hashlib.sha256(contrasena_maestra.encode()).hexdigest()
            
            with open(ARCHIVO_HASH_MAESTRA, "w") as f:
                f.write(hash_maestra)
            
            generar_y_guardar_salt()
            
            print("\n¡Contraseña Maestra creada con éxito!")
            print("Recuérdala bien, no se puede recuperar.")
            break
        else:
            print("\nLas contraseñas no coinciden o están vacías. Por favor, inténtalo de nuevo.")

def main():
    if not os.path.exists(ARCHIVO_HASH_MAESTRA):
        configurar_contrasena_maestra()
    
    clave_de_sesion = iniciar_sesion()
    
    if clave_de_sesion:
        contrasenas = cargar_datos(clave_de_sesion)
        print("Datos cargados y descifrados correctamente.")
        
if __name__ == "__main__":
    main()