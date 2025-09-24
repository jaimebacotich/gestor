# -*- coding: utf-8 -*-
import os
import hashlib
import getpass
import json
import base64
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ARCHIVO_HASH_MAESTRA = "master.hash"
ARCHIVO_CONTRASENAS = "contrasenas.json.cifrado"
ARCHIVO_SALT = "salt.key"

def derivar_clave(contrasena_maestra: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
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
    try:
        with open(ARCHIVO_CONTRASENAS, "rb") as f:
            datos_cifrados = f.read()
        fernet = Fernet(clave)
        datos_descifrados = fernet.decrypt(datos_cifrados)
        return json.loads(datos_descifrados)
    except Exception:
        print("Error al descifrar los datos. La contraseña maestra podría ser incorrecta o los datos están corruptos.")
        return None

def guardar_datos(datos: dict, clave: bytes):
    fernet = Fernet(clave)
    datos_json = json.dumps(datos, indent=4).encode()
    datos_cifrados = fernet.encrypt(datos_json)
    with open(ARCHIVO_CONTRASENAS, "w+b") as f:
        f.write(datos_cifrados)

def iniciar_sesion() -> bytes | None:
    print("--- INICIAR SESIÓN ---")
    contrasena_maestra = getpass.getpass("Ingresa tu Contraseña Maestra: ")
    if not os.path.exists(ARCHIVO_HASH_MAESTRA):
        print("Error: No se ha configurado una contraseña maestra.")
        return None
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

def mostrar_menu_principal():
    print("*********************************")
    print("*      GESTOR DE CONTRASEÑAS      *")
    print("*********************************")
    print("[1] Agregar nueva contraseña")
    print("[2] Listar contraseñas almacenadas")
    print("[3] Buscar contraseña por servicio")
    print("[4] Eliminar contraseña")
    print("[5] Cambiar contraseña maestra")
    print("[6] Salir")
    print("*********************************")

def agregar_contrasena(contrasenas: dict, clave: bytes):
    print("\n--- AGREGAR NUEVA CONTRASEÑA ---")
    nombre_servicio = input("Nombre del Servicio: ")
    usuario = input("Usuario o Correo: ")
    contrasena = getpass.getpass("Ingrese Contraseña: ")
    
    id_entrada = str(int(datetime.now().timestamp())) 
    
    contrasenas[id_entrada] = {
        "servicio": nombre_servicio,
        "usuario": usuario,
        "contrasena": contrasena,
        "fecha_creacion": datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    }
    
    guardar_datos(contrasenas, clave)
    print("\n¡Contraseña para '{}' guardada con éxito!".format(nombre_servicio))

def ver_detalle_contrasena(contrasenas: dict):
    try:
        id_seleccionado = input("Seleccione el número del servicio para ver el detalle (o '0' para volver): ")
        if id_seleccionado == '0':
            return

        claves_listadas = list(contrasenas.keys())
        id_real = claves_listadas[int(id_seleccionado) - 1]
        entrada = contrasenas[id_real]

        print("\n--- DETALLE DE '{}' ---".format(entrada['servicio']))
        print("Servicio: {}".format(entrada['servicio']))
        print("Usuario: {}".format(entrada['usuario']))
        print("Contraseña: {}".format(entrada['contrasena']))
        print("Fecha de creación: {}".format(entrada['fecha_creacion']))
        input("\nPresiona Enter para volver...")

    except (ValueError, IndexError):
        print("Selección no válida. Inténtalo de nuevo.")

def listar_contrasenas(contrasenas: dict):
    print("\n--- CONTRASEÑAS ALMACENADAS ---")
    if not contrasenas:
        print("Aún no hay contraseñas guardadas.")
        return

    print("{:<5} {:<25} {:<25} {:<20}".format("N°", "Servicio", "Usuario", "Fecha de creación"))
    print("-