#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <botan/slh_dsa.h>
#include <botan/sp_parameters.h>
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
void measure_slh_dsa(const std::string& alg_name, const std::string& base_name, const bool with_prehash)
{

    /*
    Esta función recibe por parámetros el set de parámetros a utilizar.

    Se encarga de evaluar el tiempo de ejecución y ciclos de CPU consumidos en los tres procesos principales 
    en un esquema de firma:
    - Generación de claves
    - Firma de un mensaje
    - Verificación de firma

    A medida que termine cada proceso, se imprimirán las mediciones del mismo.
    */

    try
    {
        Botan::AutoSeeded_RNG rng;

        // Construimos Sphincs_Parameters a partir del nombre
        Botan::Sphincs_Parameters params = Botan::Sphincs_Parameters::create(alg_name);

        // Verificamos que los parámetros sean correctos.
        if(!params.is_available()) {
            std::cerr << "Algoritmo '" << alg_name << "' no disponible en esta build.\n";
            return;
        }

        // Print inicial.

        std::cout << "EVALUACIÓN DE RENDIMIENTO DEL ALGORITMO SLH-DSA" << "\n"
                  << "SET DE PARÁMETROS UTILIZADOS: " << base_name << "\n"
                  << "Pre-Hash: ";
        if (with_prehash){std::cout << "Sí";}else{std::cout << "No";}
        std::cout << "\n\n\n";
    

        // -------------- GENERACIÓN DE CLAVES -----------------------

        // Tomamos mediciones de tiempo y ciclos iniciales
        auto start_keygen = std::chrono::high_resolution_clock::now();
        auto cycles_keygen_start = cpucycles();

        // Generamos la clave privada con el set de parámetros correcto
        Botan::SLH_DSA_PrivateKey priv_key(rng, params);

        // A partir de la clave privada derivamos la pública.
        Botan::SLH_DSA_PublicKey pub_key = priv_key;

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

        // -------------- GENERACIÓN DE FIRMA -----------------------
        Botan::PK_Signer signer(priv_key, rng, "Deterministic");
        Botan::secure_vector<uint8_t> msg{0x01, 0x02, 0x03, 0x04}; // Mismo mensaje de 4 bytes para los 3 algoritmos que evaluamos.

        // Mediciones inicales de la firma
        auto start_sign = std::chrono::high_resolution_clock::now();
        auto cycles_sign_start = cpucycles();

        signer.update(msg);
        auto signature = signer.signature(rng);

        // Mediciones al terminar de firmar el mensaje
        auto cycles_sign_end = cpucycles();
        auto end_sign = std::chrono::high_resolution_clock::now();

        // Imprimimos mediciones
        std::cout << "RESULTADOS DE GENERACIÓN DE FIRMA\n"
                  << "Tiempo de ejecución: " << std::chrono::duration<double>(end_sign - start_sign).count() << "s\n"
                  << "Ciclos de CPU: " << (cycles_sign_end - cycles_sign_start) << " ciclos\n";

        std::cout << "Tamaño de la firma: " << signature.size() << " bytes\n\n\n";
        

        // -------------- VERIFICACIÓN DE FIRMA -----------------------
        Botan::PK_Verifier verifier(pub_key, "Deterministic");

        // Mediciones inicales de la verificación
        auto start_verify = std::chrono::high_resolution_clock::now();
        auto cycles_verify_start = cpucycles();

        verifier.update(msg);
        bool ok = verifier.check_signature(signature);
        
        if (ok) {
            std::cout << "Firma VERIFICADA correctamente\n\n";
        } else {
            std::cerr << "Fallo en la verificación de la firma\n\n";
            return;
}


        // Mediciones finales de la verificación
        auto cycles_verify_end = cpucycles();
        auto end_verify = std::chrono::high_resolution_clock::now();

        // Imprimimos mediciones
        std::cout << "RESULTADOS DE VERIFICACIÓN DE FIRMA\n"
                  << "Tiempo de ejecución: " << std::chrono::duration<double>(end_verify - start_verify).count() << "s\n"
                  << "Ciclos de CPU: " << (cycles_verify_end - cycles_verify_start) << " ciclos\n";


    }
    catch(const std::exception& e)
    {
        std::cerr << "Excepción en measure_slh_dsa(" << alg_name << "): " << e.what() << "\n";
    }
}

int main()
{
    // Preguntamos al usuario si quiere prehash o no
    std::cout << "¿Deseas usar prehash?\n";
    std::cout << "  0) No\n";
    std::cout << "  1) Sí\n";
    std::cout << "> ";
    int opt = 0;
    std::cin >> opt;
    bool with_prehash = (opt == 1);

    // En este punto la variable with_prehash almacena un booleano en funcion de si se quiere pre-hash o no.

    // Creamos un vector con los 12 posibles sets de parámetros que tiene SLH-DSA
    std::vector<std::string> slhdsa_sets = {
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
    };

    // Damos a elegir al usuario uno de los sets de parámetros.
    std::cout << "\nElige uno de los sets de parámetros SLH-DSA:\n";
    for(size_t i = 0; i < slhdsa_sets.size(); ++i) {
        std::cout << "  " << i << ") " << slhdsa_sets[i] << "\n";
    }
    std::cout << "> ";
    int choice = 0;
    std::cin >> choice;
    // Almacenamos la eleccion en choice

    // Control de errores
    if(choice < 0 || static_cast<size_t>(choice) >= slhdsa_sets.size()) {
        std::cerr << "Opción inválida\n";
        return 1;
    }

    // 3) Construimos el nombre final que utiliza Botan
    std::string base_name = slhdsa_sets[choice]; // Nombre base del set
    
    // Cuando se utiliza prehash, Botan forma el nombre de la siguiente manera:
    // Hash-[NOMBRE_BASE]-with-[HASH_UTILIZADO_PARA_PREHASH]

    

    // Definimos la variable que contendrá el nombre final
    std::string setParametro;

    // Si con prehash, añadimos la parte "Hash-" y "-with-..."
    if(with_prehash)
    {
    // Decidimos qué hash usar de acuerdo a 'choice'
  
    std::string preHash;

    if(choice <= 1) // Se ha elegido Sha128 => prehash SHA256
         {
        preHash = "SHA256";
        }
    else if(choice <= 5) // Se ha elegido Sha192/Sha256 => prehash SHA512
        {
        preHash = "SHA512";
        }
    else if(choice <= 7)  // Se ha elegido Shake128 => prehash Shake128
        {
        preHash = "SHAKE128";
        }
    else // Se ha elegido Shake192/256 => prehash Shake256
        {
        preHash = "SHAKE256";
        }

    // Se forma el nombre completo
    setParametro = "Hash-" + base_name + "-with-" + preHash;
    }

    // No se ha elegido utilziar prehash
    else{
    // Sin prehash => nombre tal cual
    setParametro = base_name;
    }

    //Ejecutamos la medición
    measure_slh_dsa(setParametro, base_name, with_prehash);

    return 0;
}


//g++ -std=c++20 slh-dsa.cpp -I/usr/local/include/botan-3 -lbotan-3 -o SLH-DSA