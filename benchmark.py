import subprocess, csv, re, sys

ALGORITMOS = {
    1: "ML-DSA",
    2: "XMSS",
    3: "SLH-DSA"
}

# Sets de parámetros
slhdsa_sets = [
    "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
    "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"
]

xmss_sets = [
    "XMSS-SHA2_10_256", "XMSS-SHA2_16_256", "XMSS-SHA2_20_256",
    "XMSS-SHA2_10_512", "XMSS-SHA2_16_512", "XMSS-SHA2_20_512",
    "XMSS-SHAKE_10_256", "XMSS-SHAKE_16_256", "XMSS-SHAKE_20_256",
    "XMSS-SHAKE_10_512", "XMSS-SHAKE_16_512", "XMSS-SHAKE_20_512",
    "XMSS-SHA2_10_192", "XMSS-SHA2_16_192", "XMSS-SHA2_20_192",
    "XMSS-SHAKE256_10_256", "XMSS-SHAKE256_16_256", "XMSS-SHAKE256_20_256",
    "XMSS-SHAKE256_10_192", "XMSS-SHAKE256_16_192", "XMSS-SHAKE256_20_192"
]

mldsa_sets = [
    "ML-DSA-4x4",
    "ML-DSA-6x5",
    "ML-DSA-8x7"
]

def extract_float(label, text):
    match = re.search(rf"{re.escape(label)}:\s*([0-9.]+)", text)
    return float(match.group(1)) if match else -1

def extract_int(label, text):
    match = re.search(rf"{re.escape(label)}:\s*([0-9]+)", text)
    return int(match.group(1)) if match else -1

def build_slhdsa_param(param, with_prehash):
    if not with_prehash:
        return param
    if "128" in param:
        hash_str = "SHA256" if "SHA2" in param else "SHAKE128"
    elif "192" in param:
        hash_str = "SHA512" if "SHA2" in param else "SHAKE256"
    elif "256" in param:
        hash_str = "SHA512" if "SHA2" in param else "SHAKE256"
    return f"Hash-{param}-with-{hash_str}"

if __name__ == "__main__":

    print("\n------------------ EJECUCIÓN AUTOMÁTICA DE BENCHMARK COMPLETO ------------------\n")
    print("[+] SELECCIONA EL ALGORITMO:\n")

    for key, algoritmo in ALGORITMOS.items():
        print(f"[{key}] {algoritmo}")

    try:
        num_algo = int(input("\n>> "))
        if num_algo not in ALGORITMOS:
            raise Exception
    except:
        print("\nIntroduce únicamente el número [1,2,3].")
        sys.exit(1)

    algoritmo = ALGORITMOS[num_algo]
    executable = f"./{algoritmo}"
    output_file = f"{algoritmo}_Resultados.csv"

    header = ["Parametro", "Prehash", "Keygen_tiempo", "Keygen_ciclos",
              "Firma_tiempo", "Firma_ciclos", "Verificacion_tiempo", "Verificacion_ciclos",
              "Tamaño_clave_pub", "Tamaño_clave_priv", "Tamaño_firma"]

    results = []

    if algoritmo == "SLH-DSA":
        for prehash in [0, 1]:
            for param in slhdsa_sets:
                nombre = build_slhdsa_param(param, prehash)
                print(f"\n[+] Ejecutando {nombre}")
                try:
                    result = subprocess.run(
                        [executable, str(prehash), param],
                        capture_output=True,
                        timeout=60
                    )
                    output = result.stdout.decode()
                    if result.returncode != 0:
                        print("❌ Error:", result.stderr.decode())
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

    elif algoritmo == "XMSS":
        for param in xmss_sets:
            print(f"\n[+] Ejecutando {param}")
            try:
                result = subprocess.run(
                    [executable, param],
                    capture_output=True,
                    timeout=60
                )
                output = result.stdout.decode()
                if result.returncode != 0:
                    print("❌ Error:", result.stderr.decode())
                    continue

                row = [
                    param,
                    "-",  # no prehash
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
                print(f"⏰ Timeout en {param}")

    elif algoritmo == "ML-DSA":
        for param in mldsa_sets:
            print(f"\n[+] Ejecutando {param}")
            try:
                result = subprocess.run(
                    [executable, param],
                    capture_output=True,
                    timeout=60
                )
                output = result.stdout.decode()
                if result.returncode != 0:
                    print("❌ Error:", result.stderr.decode())
                    continue

                row = [
                    param,
                    "-",  # no prehash
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
                print(f"⏰ Timeout en {param}")

    # Guardar CSV
    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(results)

    print(f"\n✅ Resultados guardados en '{output_file}'")
