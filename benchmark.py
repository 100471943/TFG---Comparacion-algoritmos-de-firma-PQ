import subprocess, csv, re, sys

"""
Script para automatizar las pruebas de los tres algoritmos de firma. 
Al ejecutar el script, se dan tres opciones (1,2,3) para elegir el test completo.
Los resultados se escribirán en un CSV con nombre: ALGORITMO_Resultados.csv
"""

ALGORITMOS = {
    1: "ML-DSA",
    2: "XMSS",
    3: "SLH-DSA"
}

# Sets de parámetros SLH-DSA
slhdsa_sets = [
    "SLH-DSA-SHA2-128s",   
    "SLH-DSA-SHA2-128f",   
    "SLH-DSA-SHA2-192s",   
    "SLH-DSA-SHA2-192f",   
    "SLH-DSA-SHA2-256s",   
    "SLH-DSA-SHA2-256f",  
    "SLH-DSA-SHAKE-128s", 
    "SLH-DSA-SHAKE-128f",  
    "SLH-DSA-SHAKE-192s",  
    "SLH-DSA-SHAKE-192f",  
    "SLH-DSA-SHAKE-256s",  
    "SLH-DSA-SHAKE-256f"
]

def extract_float(label, text):
    match = re.search(rf"{re.escape(label)}:\s*([0-9.]+)", text)
    return float(match.group(1)) if match else -1

def extract_int(label, text):
    match = re.search(rf"{re.escape(label)}:\s*([0-9]+)", text)
    return int(match.group(1)) if match else -1

if __name__ == "__main__":

    print("\n------------------ EJECUCIÓN AUTOMÁTICA DE BENCHMARK COMPLETO ------------------", end="\n\n")
    print("[+] SELECCIONA EL ALGORITMO: ", end="\n\n")
    
    for key, algoritmo in ALGORITMOS.items():
        print(f"[{key}] {algoritmo}")

    try:
        num_algo = int(input("\n\n>> "))
        if num_algo not in ALGORITMOS:
            raise Exception
    except:
        print("\nIntroduce únicamente el número [1,2,3].")
        sys.exit(1)

    algoritmo_elegido = ALGORITMOS[num_algo]

    """
    if algoritmo_elegido != "SLH-DSA":
        print(f"⚠️ Automatización aún no implementada para {algoritmo_elegido}")
        sys.exit(0)

    # Ruta del ejecutable
    executable = "./SLH-DSA"

    # Fichero CSV de salida
    output_file = "SLH-DSA_Resultados.csv"
    header = ["Parametro", "Prehash", "Keygen_tiempo", "Keygen_ciclos",
              "Firma_tiempo", "Firma_ciclos", "Verificacion_tiempo", "Verificacion_ciclos",
              "Tamaño_clave_pub", "Tamaño_clave_priv", "Tamaño_firma"]

    results = []

    for prehash in [0, 1]:
        for idx, param in enumerate(slhdsa_sets):
            print(f"\n[+] Ejecutando {param} | prehash={prehash}")

            input_data = f"{prehash}\n{idx}\n"

            try:
                result = subprocess.run(
                    [executable],
                    input=input_data.encode(),
                    capture_output=True,
                    timeout=60
                )

                output = result.stdout.decode()
                if result.returncode != 0:
                    print(f"❌ Error al ejecutar {param} (prehash={prehash})")
                    print(result.stderr.decode())
                    continue

                row = [
                    param,
                    prehash,
                    extract_float("Tiempo de ejecución", output.split("RESULTADOS DE GENERACIÓN DE CLAVES")[1]),
                    extract_int("Ciclos de CPU", output.split("RESULTADOS DE GENERACIÓN DE CLAVES")[1]),
                    extract_float("Tiempo de ejecución", output.split("RESULTADOS DE GENERACIÓN DE FIRMA")[1]),
                    extract_int("Ciclos de CPU", output.split("RESULTADOS DE GENERACIÓN DE FIRMA")[1]),
                    extract_float("Tiempo de ejecución", output.split("RESULTADOS DE VERIFICACIÓN DE FIRMA")[1]),
                    extract_int("Ciclos de CPU", output.split("RESULTADOS DE VERIFICACIÓN DE FIRMA")[1]),
                    extract_int("Tamaño de la clave pública", output),
                    extract_int("Tamaño de la clave privada", output),
                    extract_int("Tamaño de la firma", output)
                ]

                results.append(row)

            except subprocess.TimeoutExpired:
                print(f"⏰ Timeout en {param} (prehash={prehash})")

    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(results)

    print(f"\n✅ Resultados guardados en '{output_file}'")"""
