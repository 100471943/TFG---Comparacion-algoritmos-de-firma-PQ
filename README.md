# Pruebas de rendimiento de esquemas de firma post-cuánticos.
Este es el repositorio con todo el código hecho para el Trabajo de Fin de Grado "Estudio comparativo del rendimiento de los estándares de firma digital post-cuánticos". Todo el código que se puede encontrar en este repositorio es propio. Únicamente en el fichero [generarRetículos.py](src/generarRetículos.py), para el cual se 
utilizó ChatGPT durante su desarrollo, tal y como se especifica en el anexo de la memoria del TFG con la declaración del uso de la IA.

Para la implenentación de los esquemas de firma se utiliza la librería criptográfica Botan: https://botan.randombit.net/

## Implementación de los esquemas de firma y sus pruebas
En primer lugar, se puede encontrar los tres programas de C++ que evalúan el rendimiento de cada esquema de firma:
- [ml-dsa.cpp](src/ml-dsa.cpp)
- [xmss.cpp](src/xmss.cpp)
- [slh-dsa.cpp](src/slh-dsa.cpp)

Cada uno de estos scripts tiene los dos modos de ejecución especificados en la memoria. El primero es una ejecución normal, sin parámetros, en la que se ejecuta una pequeña consola interactica en la que se pude elegir el conjunto de parámetros a probar y, en el caso de que esté disponible,
el utilizar o no pre-hash. El segundo modo de ejecución es pasando por parámetros el nombre del conjunto de parámetros a la hora de ejecutar el programa. Por ejemplo:
<pre> ```bash ./xmss XMSS-SHA2_10_256``` </pre>


## Fichero de automatización de pruebas
Además de los tres progrmas de C++ con las implementaciones de los esquemas y sus pruebas, se incluye un script de Python [benchmark.py](src/benchmark.py). Al ejecutarlo, se ejecuta una consola interactiva en la que se puede elegir entre cuatro opciones: ejecutar todas las pruebas 
con todos los conjuntos de parámetros de un esquema en concreto, o ejecutar todas las pruebas de todos los esquemas.

![image](https://github.com/user-attachments/assets/c16b6af5-f7c2-4788-b46d-944a654a2e68)




## Resultados de las pruebas
En los ficheros _csv_ se pueden encontrar los resultados de todas las pruebas que se han hecho para los tres esquemas. Estos resultados son los que se utilizan en la memoria del TFG.


# Instalación de la librería Botan
A continuación de presentan unos pasos generales para realizar la instalación de la librería Botan en Ubuntu. Para más información sobre la instalación en Ubuntu o en cualquier otro sistema opertivo, se puede consultar la [guía de instalación](https://botan.randombit.net/handbook/building.html) oficial de Botan.

Antes de empezar con la instalación, hay que instalar algunas dependencias:
<pre> ```bash sudo apt install git, g++, make``` </pre>

1. Clonar el repositorio de Botan `git clone https://github.com/randombit/botan.git`
2. `cd botan`
3. `./configure.py` Aquí se pueden configurar algunas opciones sobre la instalación. Para más información ver la [guía de instalación](https://botan.randombit.net/handbook/building.html)
4. `make`
5. `sudo make install`

# Compilación de los scripts de C++
Para compilar los tres programas de C++ de los tres esquemas, hay que seguir los siguientes pasos:

1. En primer lugar, hay que añadir la ruta de instalación de la librería Botan "/usr/local/lib" a la variable de entorno LD_LIBRARY_PATH. Si no se hace esto, dará error al ejecutar los scripts. Esto se avisa siempre cuando se compile con make.
  1.1. Esto se puede hacer de manera temporal con `export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH`. Si se cierra la terminal, hay que repetir este paso.
  1.2. O se puede hacer de manera permanente, modificando el fichero ~/.bashrc o el correspondiente a la shell que se esté utilizando. Por ejemplo con: `echo 'export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH' >> ~/.bashrc`.
2. Una vez añadida la ruta de instalación de Botan, se clona este repositorio: `git clone https://github.com/100471943/TFG---Comparacion-algoritmos-de-firma-PQ.git`
3. `cd TFG---Comparacion-algoritmos-de-firma-PQ`
4. `make`. Esto debería generar los tres ejecutables. Al compilar, saldrá el aviso del paso 1 por si no se ha hecho aún. Si se ha hecho correctaemente se puede ignorar.




