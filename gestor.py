# -*- coding: utf-8 -*-import os
import hashlib
import getpass

ARCHIVO_HASH_MAESTRA = "master.hash"
ARCHIVO_CONTRASENAS = "contrasenas.json.cifrado"

def configurar_contrasena_maestra():
    print("--- CONFIGURACIÓN INICIAL ---")
    print("Parece que es la primera vez que usas el gestor.")
    print("Por favor, crea tu Contraseña Maestra. La necesitarás cada vez que uses el programa.")
    
    while True:
        contrasena_maestra = getpass.getpass("Crea tu Contraseña Maestra: ")
        confirmacion_contrasena = getpass.getpass("Confirma tu Contraseña Maestra: ")
        
        if contrasena_maestra == confirmacion_contrasena:
            hash_maestra = hashlib.sha256(contrasena_maestra.encode()).hexdigest()
            
            with open(ARCHIVO_HASH_MAESTRA, "w") as f:
                f.write(hash_maestra)
            
            print("\n¡Contraseña Maestra creada con éxito!")
            print("Recuérdala bien, no se puede recuperar.")
            break
        else:
            print("\nLas contraseñas no coinciden. Por favor, inténtalo de nuevo.")

def main():
    if not os.path.exists(ARCHIVO_HASH_MAESTRA):
        configurar_contrasena_maestra()
    else:
        print("--- BIENVENIDO DE NUEVO ---")

if __name__ == "__main__":
    main()