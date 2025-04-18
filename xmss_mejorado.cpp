#include <chrono>
#include <iostream>
#include <botan/auto_rng.h> // Para generar números aleatorios mediante RNG
#include <botan/pubkey.h>   // Para la gestión de las claves
#include <botan/secmem.h>   // Para el almacenamiento seguro en memoria
#include <botan/xmss.h>     // El propio algoritmo de firma XMSS
#include <vector>
#include <ctime>            // Para medir los tiempos de ejecución



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

void measure_xmss(Botan::XMSS_Parameters::xmss_algorithm_t algo) {

    
    try {
        Botan::AutoSeeded_RNG rng;
        
        // 1. Key Generation
        auto start_keygen = std::chrono::high_resolution_clock::now();
        auto cycles_keygen_start = cpucycles();
        
        Botan::XMSS_PrivateKey priv_key(algo, rng);
        const Botan::XMSS_PublicKey& pub_key(private_key);
        
        auto cycles_keygen_end = cpucycles();
        auto end_keygen = std::chrono::high_resolution_clock::now();
        
        // 2. Signing
        Botan::secure_vector<uint8_t> msg{0x01, 0x02, 0x03, 0x04};
        Botan::PK_Signer signer(priv_key, rng, "");
        
        auto start_sign = std::chrono::high_resolution_clock::now();
        auto cycles_sign_start = cpucycles();
        
        auto sig = signer.sign_message(msg, rng);
        
        auto cycles_sign_end = cpucycles();
        auto end_sign = std::chrono::high_resolution_clock::now();
        
        // 3. Verification
        
        
        auto start_verify = std::chrono::high_resolution_clock::now();
        auto cycles_verify_start = cpucycles();
        
        Botan::PK_Verifier verifier(public_key, "");

        // verify the signature for the previously generated message.
        if(verifier.verify_message(msg, sig)) {
            std::cout << "Success.\n";
            return 0;
        } else {
            std::cout << "Error.\n";
            return 1;
        }
        
        auto cycles_verify_end = cpucycles();
        auto end_verify = std::chrono::high_resolution_clock::now();
        
        // Output results
        std::cout << "\nResults for " << priv_key.algo_name() << ":\n";
        std::cout << "Keygen: " 
                  << std::chrono::duration<double>(end_keygen - start_keygen).count() 
                  << " s, " << (cycles_keygen_end - cycles_keygen_start) << " cycles\n";
        std::cout << "Sign:   " 
                  << std::chrono::duration<double>(end_sign - start_sign).count() 
                  << " s, " << (cycles_sign_end - cycles_sign_start) << " cycles\n";
        std::cout << "Verify: " 
                  << std::chrono::duration<double>(end_verify - start_verify).count() 
                  << " s, " << (cycles_verify_end - cycles_verify_start) << " cycles\n";
        std::cout << "Signature valid: " << std::boolalpha << valid << "\n";
        
    } catch(const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }
}

int main() {
    // Test different configurations
    measure_xmss(Botan::XMSS_Parameters::XMSS_SHA2_10_256);
    //measure_xmss(Botan::XMSS_Parameters::XMSS_SHA2_10_256);
    return 0;
}