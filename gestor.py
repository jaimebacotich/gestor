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
    with open(ARCHIVO_SALT, "wb") as f: f.write(salt)
    return salt

def cargar_salt():
    with open(ARCHIVO_SALT, "rb") as f: return f.read()

def cargar_datos(clave: bytes) -> dict:
    if not os.path.exists(ARCHIVO_CONTRASENAS): return {}
    try:
        with open(ARCHIVO_CONTRASENAS, "rb") as f: datos_cifrados = f.read()
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
    with open(ARCHIVO_CONTRASENAS, "w+b") as f: f.write(datos_cifrados)

def iniciar_sesion() -> bytes | None:
    print("--- INICIAR SESIÓN ---")
    contrasena_maestra = getpass.getpass("Ingresa tu Contraseña Maestra: ")
    if not os.path.exists(ARCHIVO_HASH_MAESTRA):
        print("Error: No se ha configurado una contraseña maestra.")
        return None
    with open(ARCHIVO_HASH_MAESTRA, "r") as f: hash_guardado = f.read()
    if hashlib.sha256(contrasena_maestra.encode()).hexdigest() == hash_guardado:
        print("¡Inicio de sesión exitoso!\n")
        salt = cargar_salt()
        return derivar_clave(contrasena_maestra, salt)
    else:
        print("Contraseña Maestra incorrecta.\n")
        return None

def configurar_contrasena_maestra():
    print("--- CONFIGURACIÓN INICIAL ---")
    print("Por favor, crea tu Contraseña Maestra.")
    while True:
        contrasena_maestra = getpass.getpass("Crea tu Contraseña Maestra: ")
        confirmacion = getpass.getpass("Confirma tu Contraseña Maestra: ")
        if contrasena_maestra == confirmacion and contrasena_maestra:
            hash_maestra = hashlib.sha256(contrasena_maestra.encode()).hexdigest()
            with open(ARCHIVO_HASH_MAESTRA, "w") as f: f.write(hash_maestra)
            generar_y_guardar_salt()
            print("\n¡Contraseña Maestra creada con éxito!")
            break
        else:
            print("\nLas contraseñas no coinciden o están vacías.")

def mostrar_menu_principal():
    print("\n*********************************")
    print("*      GESTOR DE CONTRASEÑAS      *")
    print("*********************************")
    print("[1] Agregar nueva contraseña")
    print("[2] Listar contraseñas")
    print("[3] Buscar contraseña")
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
        "servicio": nombre_servicio, "usuario": usuario, "contrasena": contrasena,
        "fecha_creacion": datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    }
    guardar_datos(contrasenas, clave)
    print(f"\n¡Contraseña para '{nombre_servicio}' guardada con éxito!")

def ver_detalle_contrasena(contrasenas: dict, ids_mostradas: list):
    try:
        id_seleccionado = input("Seleccione el número para ver el detalle (o '0' para volver): ")
        if id_seleccionado == '0': return
        id_real = ids_mostradas[int(id_seleccionado) - 1]
        entrada = contrasenas[id_real]
        print(f"\n--- DETALLE DE '{entrada['servicio']}' ---")
        for campo, valor in entrada.items(): print(f"{campo.capitalize()}: {valor}")
        input("\nPresiona Enter para volver...")
    except (ValueError, IndexError):
        print("Selección no válida.")

def listar_contrasenas(contrasenas: dict, titulo: str = "CONTRASEÑAS ALMACENADAS"):
    print(f"\n--- {titulo} ---")
    if not contrasenas:
        print("No hay contraseñas para mostrar.")
        return
    
    print("{:<5} {:<25} {:<25} {:<20}".format("N°", "Servicio", "Usuario", "Fecha de creación"))
    print("-