#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <botan/dilithium.h>
#include <chrono>
#include <iostream>
#include <string>
#include <vector>

// Función para medir ciclos de CPU
long long cpucycles(void){

    /*
    Cuando se hace una llamada a la función cpucycles, ésta devuelve el número total 
    de ciclos de CPU consumidos desde el inicio del programa hasta el instante de la 
    llamada a la función
    */

  unsigned long long result;
  asm volatile(".byte 15;.byte 49;shlq $32,%%rdx;orq %%rdx,%%rax"
    : "=a" (result) ::  "%rdx");
  return result;
};

// Función de evaluación de ML-DSA
void measure_mldsa(const Botan::DilithiumMode::Mode mode, const std::string& nombre_parametro) {

    /*
    Esta función recibe por parámetros el set de parámetros a utilizar.

    Se encarga de evaluar el tiempo de ejecución y ciclos de CPU consumidos en los tres procesos principales 
    en un esquema de firma:
    - Generación de claves
    - Firma de un mensaje
    - Verificación de firma

    A medida que termine cada proceso, se imprimirán las mediciones del mismo.
    */

    try {
        Botan::AutoSeeded_RNG rng;

        // Seleccionamos el modo
        Botan::DilithiumMode mldsa_mode(mode);

        if(!mldsa_mode.is_ml_dsa()) {
            std::cerr << "El modo seleccionado no es ML-DSA.\n";
            return;
        }

        std::cout << "EVALUACIÓN DE RENDIMIENTO DEL ALGORITMO ML-DSA\n";
        std::cout << "SET DE PARÁMETROS UTILIZADOS: " << nombre_parametro << "\n\n";

        // ---------------------- GENERACIÓN DE CLAVES ----------------------
        
        // Tomamos mediciones de tiempo y ciclos iniciales
        auto start_keygen = std::chrono::high_resolution_clock::now();
        auto cycles_keygen_start = cpucycles();

        // Se crea la clave privada con el modo de ml-dsa elegido y se deriva la pública
        Botan::Dilithium_PrivateKey priv_key(rng, mldsa_mode);
        auto pub_key = priv_key.public_key();

        // Se crea el firmador con la clave privada
        Botan::PK_Signer signer(priv_key, rng, "Randomized"); // Randomized para usar la versión hedged

        // Mediciones finales de la generación de claves
        auto cycles_keygen_end = cpucycles();
        auto end_keygen = std::chrono::high_resolution_clock::now();

        // Imprimimos las primeras mediciones.
        std::cout << "RESULTADOS DE GENERACIÓN DE CLAVES\n"
                  << "Tiempo de ejecución: " << std::chrono::duration<double>(end_keygen - start_keygen).count() << "s\n"
                  << "Ciclos de CPU: " << (cycles_keygen_end - cycles_keygen_start) << " ciclos\n";

        std::cout << "Tamaño de la clave pública: " << pub_key->public_key_bits().size() << " bytes\n";
        std::cout << "Tamaño de la clave privada: " << priv_key.raw_private_key_bits().size() << " bytes\n\n\n";

        // ---------------- GENERACIÓN DE FIRMA -----------------------
        Botan::secure_vector<uint8_t> msg{0x01, 0x02, 0x03, 0x04};

        // Mediciones iniciales de la firma
        auto start_sign = std::chrono::high_resolution_clock::now();
        auto cycles_sign_start = cpucycles();

        // Se firma el mensaje
        signer.update(msg.data(), msg.size()); 
	    std::vector<uint8_t> signature = signer.signature(rng);

        // Mediciones finales de la firma
        auto cycles_sign_end = cpucycles();
        auto end_sign = std::chrono::high_resolution_clock::now();

        // Imprimimos mediciones
        std::cout << "RESULTADOS DE GENERACIÓN DE FIRMA\n"
                  << "Tiempo de ejecución: " << std::chrono::duration<double>(end_sign - start_sign).count() << "s\n"
                  << "Ciclos de CPU: " << (cycles_sign_end - cycles_sign_start) << " ciclos\n";

        std::cout << "Tamaño de la firma: " << signature.size() << " bytes\n\n\n";

        // ---------------- VERIFICACIÓN DE FIRMA -----------------------
        
        // Mediciones inicales de la verificación
        auto start_verify = std::chrono::high_resolution_clock::now();
        auto cycles_verify_start = cpucycles();


        // Se genera el verificador, utilizando la versión hedged.
        Botan::PK_Verifier verifier(*pub_key, "");
        
        // Y se verifica la firma del mensaje
        verifier.update(msg.data(), msg.size());
        if(verifier.check_signature(signature.data(), signature.size())) {
            std::cout << "Firma Verificada." << std::endl;
            
        } else {
            std::cout << "Firma Errónea." << std::endl;
            
        }


        // Mediciones finales de la verificación
        auto cycles_verify_end = cpucycles();
        auto end_verify = std::chrono::high_resolution_clock::now();

        // Imprimimos mediciones
        std::cout << "RESULTADOS DE VERIFICACIÓN DE FIRMA\n"
                  << "Tiempo de ejecución: " << std::chrono::duration<double>(end_verify - start_verify).count() << "s\n"
                  << "Ciclos de CPU: " << (cycles_verify_end - cycles_verify_start) << " ciclos\n";

    } catch(const std::exception& e) {
        std::cerr << "Excepción en measure_mldsa(" << nombre_parametro << "): " << e.what() << "\n";
    }
}

int main(int argc, char* argv[])
{
    // Vector con los 3 posibles modos de ML-DSA
    std::vector<std::pair<std::string, Botan::DilithiumMode::Mode>> mldsa_sets = {
        {"ML-DSA-4x4", Botan::DilithiumMode::ML_DSA_4x4},
        {"ML-DSA-6x5", Botan::DilithiumMode::ML_DSA_6x5},
        {"ML-DSA-8x7", Botan::DilithiumMode::ML_DSA_8x7}
    };

    std::string nombre_parametro;               // Nombre string del set elegido
    Botan::DilithiumMode::Mode modo_seleccionado; // Enum correspondiente

    /*
    DOS POSIBLES USOS DEL SCRIPT: 
    [1] -> Pasando el set de parámetros como argumento:
            ./ML-DSA NOMBRE_SET
            Ejemplo:
            ./ML-DSA ML-DSA-4x4

    [2] -> Modo interactivo si no se pasa ningún argumento:
            ./ML-DSA
    */

    // --- Caso 1: modo automático con argumento ---
    if(argc == 2)
    {
        nombre_parametro = argv[1];

        // Buscar el modo correspondiente
        auto it = std::find_if(
            mldsa_sets.begin(), mldsa_sets.end(),
            [&](const auto& pair) { return pair.first == nombre_parametro; });

        if(it == mldsa_sets.end()) {
            std::cerr << "Set de parámetros inválido.\n";
            return 1;
        }

        modo_seleccionado = it->second;
    }
    // --- Caso 2: modo interactivo ---
    else if(argc == 1)
    {
        std::cout << "\nElige uno de los modos de ML-DSA:\n";
        for(size_t i = 0; i < mldsa_sets.size(); ++i) {
            std::cout << "  " << i << ") " << mldsa_sets[i].first << "\n";
        }
        std::cout << "> ";
        int choice = 0;
        std::cin >> choice;

        if(choice < 0 || static_cast<size_t>(choice) >= mldsa_sets.size()) {
            std::cerr << "Opción inválida\n";
            return 1;
        }

        nombre_parametro = mldsa_sets[choice].first;
        modo_seleccionado = mldsa_sets[choice].second;
    }
    // --- Error de uso ---
    else
    {
        std::cerr << "Uso incorrecto.\n";
        std::cerr << "Modo interactivo: ./ML-DSA\n";
        std::cerr << "Modo automático:  ./ML-DSA <set_de_parametros>\n";
        return 1;
    }

    // Ejecutamos la evaluación de rendimiento
    measure_mldsa(modo_seleccionado, nombre_parametro);

    return 0;
}
