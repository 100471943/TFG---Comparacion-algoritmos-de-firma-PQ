#include <botan/auto_rng.h> // Para generar números aleatorios mediante RNG
#include <botan/pubkey.h>   // Para la gestión de las claves
#include <botan/secmem.h>   // Para el almacenamiento seguro en memoria
#include <botan/xmss.h>     // El propio algoritmo de firma XMSS
#include <iostream>
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

// Ejecución principal del algoritmo, incluyendo las diferentes mediciones.
int main() {
	/*
    El objetivo principal de este programa es medir el tiempo y los ciclos de cpu consumidos 
    en todo el proceso de firma y verificación (de la firma) de un mensaje de 4 bytes {0x01, 0x02, 0x03, 0x04}
    Se hacen mediciones sobre la generación de las claves, el proceso de firma del mensaje y la verificación
    de la propia firma.

    El resultado de estas mediciones se imprimirá por consola, expresando cada una en segundos y ciclos de cpu

    */
    
    // Las variables TT* almacenan los ciclos de CPU consumidos en diferentes instantes.
	unsigned long long TT0,TT1,TT2,TT3, TT4;

    // Las variables t* almacenan el tiempo de ejecución en diferentes instantes.
	unsigned long long t0, t1, t2, t3, t4;
	
    // -------------------------------------- INICIO DEL ALGORITMO DE FIRMA --------------------------------------
    
    t0=t1=t2=t3=t4=clock(); // Se inicializan todas con el instante inicial del algoritmo.
    TT0,TT1,TT2,TT3, TT4=cpucycles(); // Lo mismo para los ciclos de CPU

    // Se instancia un generador de números aleatorios criptográficamente seguro.
	Botan::AutoSeeded_RNG rng1;
	

    // ----------- GENERACIÓN DE CLAVES -------------
	
	// create a new public/private key pair using SHA2 256 as hash
	//Botan::XMSS_PrivateKey private_key1(Botan::XMSS_Parameters::xmss_algorithm_t::XMSS_SHA2_10_256, rng1);
	//Botan::XMSS_PrivateKey private_key1(Botan::XMSS_Parameters::xmss_algorithm_t::XMSS_SHA2_16_256, rng1);
	//Botan::XMSS_PrivateKey private_key1(Botan::XMSS_Parameters::xmss_algorithm_t::XMSS_SHA2_20_256, rng1);
	
	//Botan::XMSS_PrivateKey private_key1(Botan::XMSS_Parameters::xmss_algorithm_t::XMSS_SHA2_10_512, rng1);
	//Botan::XMSS_PrivateKey private_key1(Botan::XMSS_Parameters::xmss_algorithm_t::XMSS_SHA2_16_512, rng1);
	//Botan::XMSS_PrivateKey private_key1(Botan::XMSS_Parameters::xmss_algorithm_t::XMSS_SHA2_20_512, rng1);
	
	//Botan::XMSS_PrivateKey private_key1(Botan::XMSS_Parameters::xmss_algorithm_t::XMSS_SHAKE_10_256, rng1);
	//Botan::XMSS_PrivateKey private_key1(Botan::XMSS_Parameters::xmss_algorithm_t::XMSS_SHAKE_16_256, rng1);
	//Botan::XMSS_PrivateKey private_key1(Botan::XMSS_Parameters::xmss_algorithm_t::XMSS_SHAKE_20_256, rng1);
	
	//Botan::XMSS_PrivateKey private_key1(Botan::XMSS_Parameters::xmss_algorithm_t::XMSS_SHAKE_10_512, rng1);
	//Botan::XMSS_PrivateKey private_key1(Botan::XMSS_Parameters::xmss_algorithm_t::XMSS_SHAKE_16_512, rng1);
	
    // Se genera una clave privada (con el tipo de dato propio de Botan para las sk de XMSS)
    // En este caso se utiliza SHAKE con una estructura de 20 niveles y clave de 512 bits, además del RNG previamente instanciado
    Botan::XMSS_PrivateKey private_key1(Botan::XMSS_Parameters::xmss_algorithm_t::XMSS_SHAKE_20_512, rng1);
	
    // A partir de la clave privada se extrae la clave pública
	const Botan::XMSS_PublicKey& public_key1(private_key1);

	// Se crea el "firmador" (objeto instanciado que se encarga de firmar mensajes con la clave privada)
	Botan::PK_Signer signer1(private_key1, rng1, "");


    // Como ya ha termiando el proceso de generar las claves, se mide para este instante:

    t1=clock(); // El tiempo de ejecución
    TT1= cpucycles(); // Los ciclos de CPU consumidos

    // Y se imprimen las mediciones por pantalla
	std::cout << "Tiempo transcurrido para la generación de claves: " << (double(t1-t0)/CLOCKS_PER_SEC) << " sg."<< std::endl;
    std::cout << "Ciclos de CPU consumidos para la generación de claves: " << TT1-TT0 << std::endl;


    // ----------- FIRMA DEL MENSAJE -------------
	
	
	// Se crea el mensaje de 4 bytes. Se utilizará este mismo mensaje para comparar los diferentes algoritmos de firma
	Botan::secure_vector<uint8_t> msg1{0x01, 0x02, 0x03, 0x04};

    // De nuevo se hacen las mediciones en el instante inicial del proceso de firma del mensaje. (se reutilizan las variables t1 y TT1)
	t1=clock();
    TT1=cpucycles();

    
	signer1.update(msg1.data(), msg1.size()); // Se almacena el mensaje y su tamaño en el objeto firmador
	std::vector<uint8_t> sig1 = signer1.signature(rng1); // Y se procede a firmar

    // Se toman las mediciones al final del proceso de firma
	t2=clock();
    TT2=cpucycles();
	std::cout << "Tiempo transcurrido para la firma del mensaje: " << (double(t2-t1)/CLOCKS_PER_SEC) << " sg."<< std::endl;
    std::cout << "Ciclos de CPU consumidos para la firma del mensaje: " << TT2-TT1 << std::endl;
	
    // ----------- VERIFICACIÓN DE LA FIRMA ------------- 
    
    
    // Se toman las mediciones iniciales
	t1=clock();
    TT1 = cpucycles();


	// Al igual que con el firmador, se crea un verificador con la clave pública (del firmador)
	Botan::PK_Verifier verifier1(public_key1, "");

	// Se almacena en el objeto verificador el mensaje original
	verifier1.update(msg1.data(), msg1.size());
	// Y se procede a verificar la firma
	if(verifier1.check_signature(sig1.data(), sig1.size())) {
		std::cout << "Success." << std::endl;
		
	} else {
		std::cout << "Error." << std::endl;
		
	}

    // Se toman las mediciones en el instante que termina el proceso de verificación y se imprimen.
    t2 = clock();
    TT2 = cpucycles();
	std::cout << "Tiempo transcurrido para la verificación de la firma: " << (double(t2-t1)/CLOCKS_PER_SEC) << " sg."<< std::endl;
    std::cout << "Ciclos de CPU consumidos para la verificación de la firma: " << TT2-TT1 << std::endl;


    // Por último se toman las mediciones al final del algoritmo para obtener el tiempo total.
	t2 = clock();
	TT2 = cpucycles();
	
	std::cout << std::endl << std::endl << "Tiempo total de ejecución del algoritmo de firma XMSS: " << (double(t2-t0)/CLOCKS_PER_SEC) << " sg."<< std::endl;
	std::cout << "Ciclos de CPU totales consumidos por el algoritmo de firma XMSS: " << TT2-TT0 << std::endl;


   return 0;
	
}

//g++ -std=c++20 xmss.cpp -I/usr/local/include/botan-3 -lbotan-3