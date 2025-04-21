import subprocess, csv, re, sys

ALGORITMOS = {
    0: "TODOS",
    1: "ML-DSA",
    2: "XMSS",
    3: "SLH-DSA"
}

# Sets de parámetros
SLHDSA_PARAMS = [
    "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
    "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"
]

XMSS_PARAMS = [
    "XMSS-SHA2_10_256", "XMSS-SHA2_16_256", "XMSS-SHA2_20_256",
    "XMSS-SHA2_10_512", "XMSS-SHA2_16_512", "XMSS-SHA2_20_512",
    "XMSS-SHAKE_10_256", "XMSS-SHAKE_16_256", "XMSS-SHAKE_20_256",
    "XMSS-SHAKE_10_512", "XMSS-SHAKE_16_512", "XMSS-SHAKE_20_512",
    "XMSS-SHA2_10_192", "XMSS-SHA2_16_192", "XMSS-SHA2_20_192",
    "XMSS-SHAKE256_10_256", "XMSS-SHAKE256_16_256", "XMSS-SHAKE256_20_256",
    "XMSS-SHAKE256_10_192", "XMSS-SHAKE256_16_192", "XMSS-SHAKE256_20_192"
]

MLDSA_PARAMS = [
    "ML-DSA-4x4",
    "ML-DSA-6x5",
    "ML-DSA-8x7"
]

CABECERAS = ["Parametro", "Prehash", "Keygen_tiempo", "Keygen_ciclos","Tamaño_clave_pub", "Tamaño_clave_priv",
              "Firma_tiempo", "Firma_ciclos", "Tamaño_firma", "Verificacion_tiempo", "Verificacion_ciclos",
              "Tiempo total", "Ciclos_totales"
              ]
            
# Resultados de los diferntes sets de parámetros
resultados = []

# Formato de salida CSV
datos = [CABECERAS]

# Contador de fallos. Un benchmark de un set falla cuando hay un error en la ejecución o la firma no se verifica correctamente.
FALLOS = 0 

# Función para extraer el valor de la línea
def extraer_valor(linea: str):
    """
    Busca un número en la línea y lo convierte a int o float.
    Si no hay número, devuelve None.
    """
    coincidencia = re.search(r"[-+]?\d*\.\d+|\d+", linea)
    if coincidencia:
        valor_str = coincidencia.group(0)
        # Convertir a float si contiene punto decimal, si no, a int
        return float(valor_str) if '.' in valor_str else int(valor_str)
    return None


def escribirCSV(algoritmo):
    try:
        with open(f"{algoritmo}-Resultados.csv", mode="w", newline="") as archivo:
                writer = csv.writer(archivo)
                writer.writerows(datos)

        archivo.close()
            
        print(f"\nResultados guardados en '{algoritmo}-Resultados.csv'")
        
    except Exception as e:
        print(f"Error al guardar los resultados: {e}")
        sys.exit(1)


def extraer_resultados(salida):
    global resultados,datos, CABECERAS
    """
    Extrae los resultados de la salida del comando y los guarda en un csv.
    """
    # En este punto resultados ya tiene los dos primeros valores (parametro y prehash)
    # El resto de valores van a venir en orden.
    for linea in salida.splitlines():
        valor = extraer_valor(linea)
        if valor is not None:
            resultados.append(valor)
        else:
            if "Firma Errónea" in linea:
                FALLOS += 1
                print("Firma Errónea.")

    # Se calculan los ciclos totales y el tiempo total
    ciclos_totales = resultados[3] + resultados[7] + resultados[10]
    tiempo_total = resultados[2] + resultados[6] + resultados[9]
    resultados.append(tiempo_total)
    resultados.append(ciclos_totales)

    # Se añaden los resultados a la lista de datos
    datos.append(resultados)
    return 0


def ejecutar_comando(algoritmo, param, prehash=3): # PreHash = 3 -> No se utiliza en este algoritmo.
    """
    Ejecuta un comando en la terminal y devuelve la salida.
    """
    print(f"\n[+] EJECUTANDO {param}", end="")
    comando = [f"./{algoritmo}", param]
    if prehash!= 3:
        print(f"(prehash={"Sí" if prehash else "No"})", end="")
        comando.insert(1, str(prehash))
    print()

    resultado = subprocess.run(
        comando,
        capture_output=True,
        text=True,
    )
    salida = resultado.stdout
    if resultado.returncode != 0:
        print(f"Error en la ejecución de {param} (prehash={"Sí" if prehash else "No"})")
             
    # Extraer los resultados de la salida
    extraer_resultados(salida)
    return resultado.returncode


if __name__ == "__main__":

    print("\n------------------ EJECUCIÓN AUTOMÁTICA DE BENCHMARK COMPLETO ------------------\n")

    print("[+] SELECCIONA EL ALGORITMO:\n")

    
    
    for key, algoritmo in ALGORITMOS.items():
        print(f"[{key}] {algoritmo}")
    

    try:
        num_algo = int(input("\n>> "))
        if num_algo not in ALGORITMOS or num_algo != 0:
            raise Exception
    except:
        print("\nIntroduce únicamente el número [0,1,2,3].")
        sys.exit(1)

    algoritmo = ALGORITMOS[num_algo]
    
    
    print("\n[+] EJECUTANDO BENCHMARK PARA EL ALGORITMO:", algoritmo)

    if algoritmo == "SLH-DSA" or algoritmo == "TODOS":
        for prehash in [0, 1]:
            for param in SLHDSA_PARAMS:

                resultados = [param]
                if prehash == 0:
                    resultados.append("No")
                else:
                    resultados.append("Sí")

                code = ejecutar_comando("SLH-DSA", param, prehash)
                if code != 0:
                    FALLOS += 1

        # Una vez se han probado todos los parámetros, se guardan los resultados en el CSV\
        escribirCSV("SLH-DSA")
        
    if algoritmo == "XMSS" or algoritmo == "TODOS":
        
        for param in XMSS_PARAMS:

            resultados = [param, "N/A"]

            code = ejecutar_comando("XMSS", param)

            if code != 0:
                FALLOS += 1

        # Una vez se han probado todos los parámetros, se guardan los resultados en el CSV\
        escribirCSV("XMSS")

    if algoritmo == "ML-DSA" or algoritmo == "TODOS":
        
        for param in MLDSA_PARAMS:
            resultados = [param, "N/A"]

            code = ejecutar_comando("ML-DSA", param)
            
            if code != 0:
                FALLOS += 1

        # Una vez se han probado todos los parámetros, se guardan los resultados en el CSV\
        escribirCSV("ML-DSA")

    print("\n[+] BENCHMARK FINALIZADO")
    print(f"[+] FALLOS: {FALLOS}")