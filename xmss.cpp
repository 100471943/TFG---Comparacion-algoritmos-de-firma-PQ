#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <botan/xmss.h>
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


// Función principal
void measure_xmss(const std::string& param_set) {
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

        

        std::cout << "EVALUACIÓN DE RENDIMIENTO DEL ALGORITMO XMSS\n";
        std::cout << "SET DE PARÁMETROS UTILIZADOS: " << param_set << "\n\n";

        // ---------------------- GENERACIÓN DE CLAVES ----------------------
        // Tomamos mediciones de tiempo y ciclos iniciales
        auto start_keygen = std::chrono::high_resolution_clock::now();
        auto cycles_keygen_start = cpucycles();


        Botan::XMSS_Parameters::xmss_algorithm_t algo_id = Botan::XMSS_Parameters::xmss_id_from_string(param_set);

        // Generamos la clave privada con el set de parámetros correcto
        Botan::XMSS_PrivateKey priv_key(algo_id, rng);
        
        // A partir de la clave privada derivamos la pública.
        const Botan::XMSS_PublicKey& pub_key(priv_key);

        // Se crea el firmador con la clave privada
        Botan::PK_Signer signer(priv_key, rng, "");

        // Tomamos mediciones cuando termina el proceso de keygen
        auto cycles_keygen_end = cpucycles();
        auto end_keygen = std::chrono::high_resolution_clock::now();

        // Imprimimos las primeras mediciones.
        std::cout << "RESULTADOS DE GENERACIÓN DE CLAVES\n"
                  << "Tiempo de ejecución: " << std::chrono::duration<double>(end_keygen - start_keygen).count() << "s\n"
                  << "Ciclos de CPU: " << (cycles_keygen_end - cycles_keygen_start) << " ciclos\n";

        auto pk_bits = pub_key.public_key_bits();
        auto sk_bits = priv_key.private_key_bits();

        std::cout << "Tamaño de la clave pública: " << pk_bits.size() << " bytes\n";
        std::cout << "Tamaño de la clave privada: " << sk_bits.size() << " bytes\n\n\n";

        // --------------- GENERACIÓN DE FIRMA -----------------------
        
        // Mensaje fijo a firmar
        Botan::secure_vector<uint8_t> msg{0x01, 0x02, 0x03, 0x04};
        
        // Mediciones iniciales de la firma
        auto start_sign = std::chrono::high_resolution_clock::now();
        auto cycles_sign_start = cpucycles();

        // Se firma el mensaje
        signer.update(msg.data(), msg.size()); 
	    std::vector<uint8_t> signature = signer.signature(rng);

        // Mediciones al terminar de firmar el mensaje
        auto cycles_sign_end = cpucycles();
        auto end_sign = std::chrono::high_resolution_clock::now();

        // Imprimimos mediciones
        std::cout << "RESULTADOS DE GENERACIÓN DE FIRMA\n"
                  << "Tiempo de ejecución: " << std::chrono::duration<double>(end_sign - start_sign).count() << "s\n"
                  << "Ciclos de CPU: " << (cycles_sign_end - cycles_sign_start) << " ciclos\n";

        std::cout << "Tamaño de la firma: " << signature.size() << " bytes\n\n\n";

        // -------------- VERIFICACIÓN DE FIRMA -----------------------
        
        // Mediciones inicales de la verificación
        auto start_verify = std::chrono::high_resolution_clock::now();
        auto cycles_verify_start = cpucycles();

        // Se crea el verificador
        Botan::PK_Verifier verifier(pub_key, "");

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

        std::cout << "RESULTADOS DE VERIFICACIÓN DE FIRMA\n"
                  << "Tiempo de ejecución: " << std::chrono::duration<double>(end_verify - start_verify).count() << "s\n"
                  << "Ciclos de CPU: " << (cycles_verify_end - cycles_verify_start) << " ciclos\n";


    } catch (const std::exception& e) {
        std::cerr << "Excepción en measure_xmss: " << e.what() << "\n";
    }
}

int main(int argc, char* argv[])
{
    // Vector con los posibles sets de parámetros que tiene XMSS
    std::vector<std::string> xmss_sets = {
        "XMSS-SHA2_10_256", "XMSS-SHA2_16_256", "XMSS-SHA2_20_256",
        "XMSS-SHA2_10_512", "XMSS-SHA2_16_512", "XMSS-SHA2_20_512",
        "XMSS-SHAKE_10_256", "XMSS-SHAKE_16_256", "XMSS-SHAKE_20_256",
        "XMSS-SHAKE_10_512", "XMSS-SHAKE_16_512", "XMSS-SHAKE_20_512",
        "XMSS-SHA2_10_192", "XMSS-SHA2_16_192", "XMSS-SHA2_20_192",
        "XMSS-SHAKE256_10_256", "XMSS-SHAKE256_16_256", "XMSS-SHAKE256_20_256",
        "XMSS-SHAKE256_10_192", "XMSS-SHAKE256_16_192", "XMSS-SHAKE256_20_192"
    };

    std::string set_param; // Nombre del set de parámetros

    /*
    DOS POSIBLES USOS DEL SCRIPT: 
    [1] -> Pasando el set de parámetros por argumento al ejecutar:
            ./XMSS NOMBRE_SET
            Ejemplo: 
            ./XMSS XMSS-SHA2_20_256  
    
    [2] -> Modo interactivo si no se pasa ningún parámetro:
           ./XMSS
    */

    // Caso 1: Set de parámetros pasado por línea de comandos
    if(argc == 2)
    {
        set_param = argv[1];

        // Comprobamos si el set existe
        auto it = std::find(xmss_sets.begin(), xmss_sets.end(), set_param);
        if(it == xmss_sets.end()) {
            std::cerr << "Set de parámetros inválido.\n";
            return 1;
        }
    }
    // Caso 2: Modo interactivo
    else if(argc == 1)
    {
        std::cout << "\nElige uno de los sets de parámetros XMSS:\n";
        for(size_t i = 0; i < xmss_sets.size(); ++i) {
            std::cout << "  " << i << ") " << xmss_sets[i] << "\n";
        }
        std::cout << "> ";
        int choice = 0;
        std::cin >> choice;

        if(choice < 0 || static_cast<size_t>(choice) >= xmss_sets.size()) {
            std::cerr << "Opción inválida.\n";
            return 1;
        }

        // Se guarda el set de parámetros elegido
        set_param = xmss_sets[choice];
    }
    // Caso de uso incorrecto
    else
    {
        std::cerr << "Uso incorrecto.\n";
        std::cerr << "Modo interactivo: ./XMSS\n";
        std::cerr << "Modo automático:  ./XMSS <set_de_parametros>\n";
        return 1;
    }

    // Llamamos a la función principal con el set elegido
    measure_xmss(set_param);

    return 0;
}
