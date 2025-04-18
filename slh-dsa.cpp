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
        //Botan::SLH_DSA_PublicKey pub_key = priv_key;
        auto pub_key = priv_key.public_key();

        // Se crea el firmador con la clave privada
        Botan::PK_Signer signer(priv_key, rng, "Randomized");

        // Tomamos mediciones cuando termina el proceso de keygen
        auto cycles_keygen_end = cpucycles();
        auto end_keygen = std::chrono::high_resolution_clock::now();

        // Imprimimos las primeras mediciones.
        std::cout << "RESULTADOS DE GENERACIÓN DE CLAVES\n"
                  << "Tiempo de ejecución: " << std::chrono::duration<double>(end_keygen - start_keygen).count() << "s\n"
                  << "Ciclos de CPU: " << (cycles_keygen_end - cycles_keygen_start) << " ciclos\n";

        

        std::cout << "Tamaño de la clave pública: " << pub_key->public_key_bits().size() << " bytes\n";
        std::cout << "Tamaño de la clave privada: " << priv_key.private_key_bits().size() << " bytes\n\n\n";

        // -------------- GENERACIÓN DE FIRMA -----------------------
        Botan::secure_vector<uint8_t> msg{0x01, 0x02, 0x03, 0x04}; // Mismo mensaje de 4 bytes para los 3 algoritmos que evaluamos.
        
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

        // Se genera el verificador, utilizando la versión hedged.
        Botan::PK_Verifier verifier(*pub_key, "Randomized");
        
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


    }
    catch(const std::exception& e)
    {
        std::cerr << "Excepción en measure_slh_dsa(" << alg_name << "): " << e.what() << "\n";
    }
}


//g++ -std=c++20 slh-dsa.cpp -I/usr/local/include/botan-3 -lbotan-3 -o SLH-DSA

int main(int argc, char* argv[])
{
 
    // Vector con los 12 posibles sets de parámetros
    std::vector<std::string> slhdsa_sets = {
        "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"
    };



    bool with_prehash = false; // Si se quiere utilizar preHash
    std::string base_name;     // Nombre base del set de parámetros
    std::string setParametro;  // Nombre final Botan (incluyendo prehash o no)


    /*
    DOS POSIBLES USOS DEL SCRIPT: 
    [1] -> Pasando el uso del prehash y el set de parámetros por parámetros al ejecutar: 
            ./SLH-DSA WITH_PREHASH NOMRE_SET
            1 = con preHash, 0 = sin preHash
            Ejemplo: 
            ./SLH-DSA 1 SLH-DSA-SHA2-128s  
    
    [2] -> Modo interactivo después de ejecutar normal el script
           ./SLH-DSA
    
    
    */ 


   // Caso 1
    if(argc == 3)
    {
        // Leer argumentos desde línea de comandos
        with_prehash = (std::string(argv[1]) == "1");
        base_name = argv[2];


        // Se busca el set
        auto it = std::find(slhdsa_sets.begin(), slhdsa_sets.end(), base_name);
        if(it == slhdsa_sets.end()) {
            std::cerr << "Set de parámetros inválido.\n";
            return 1;
        }

        int choice = std::distance(slhdsa_sets.begin(), it);

        // Caso con prehash
        if(with_prehash)
        {
            // Se elige el prehash a utilizar en función del set elegido.
            std::string preHash;
            if(choice <= 1) preHash = "SHA256";
            else if(choice <= 5) preHash = "SHA512";
            else if(choice <= 7) preHash = "SHAKE128";
            else preHash = "SHAKE256";

            setParametro = "Hash-" + base_name + "-with-" + preHash;
        }
        // Si no se utiliza prehash, se utiliza directamente el nombre base del set de parámetros
        else {
            setParametro = base_name;
        }
    }
    else if(argc == 1)
    {
        // --- Modo interactivo ---
        std::cout << "¿Deseas usar prehash?\n  0) No\n  1) Sí\n> ";
        int opt = 0;
        std::cin >> opt;
        with_prehash = (opt == 1);

        std::cout << "\nElige uno de los sets de parámetros SLH-DSA:\n";
        for(size_t i = 0; i < slhdsa_sets.size(); ++i) {
            std::cout << "  " << i << ") " << slhdsa_sets[i] << "\n";
        }
        std::cout << "> ";
        int choice = 0;
        std::cin >> choice;

        if(choice < 0 || static_cast<size_t>(choice) >= slhdsa_sets.size()) {
            std::cerr << "Opción inválida\n";
            return 1;
        }

        // Se coge el nombre base elegido
        base_name = slhdsa_sets[choice];

        // Caso de elegir con preHash
        if(with_prehash)
        {
            // Se elige el prehash a utilizar en función del set elegido.
            std::string preHash;
            if(choice <= 1) preHash = "SHA256";
            else if(choice <= 5) preHash = "SHA512";
            else if(choice <= 7) preHash = "SHAKE128";
            else preHash = "SHAKE256";

            setParametro = "Hash-" + base_name + "-with-" + preHash;
        }
        else {
            setParametro = base_name;
        }
    }
    // Control de errores
    else
    {
        std::cerr << "Uso incorrecto.\n";
        std::cerr << "Modo interactivo: ./SLH-DSA\n";
        std::cerr << "Modo automático:  ./SLH-DSA <with_prehash: 0|1> <set_de_parametros>\n";
        return 1;
    }

    // Una vez seleccionadas las elecciones, se llama a la función principal para medir.
    measure_slh_dsa(setParametro, base_name, with_prehash);
    return 0;
}
