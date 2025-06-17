import numpy as np
import matplotlib.pyplot as plt

# Vectores base
v1 = np.array([4, -1])
v2 = np.array([3, -2])

# Rango de coeficientes enteros
rango = range(-6, 7)

# Generar puntos del retículo
reticulo = []
indices = []
for i in rango:
    for j in rango:
        punto = i * v1 + j * v2
        reticulo.append(punto)
        indices.append((i, j))
reticulo = np.array(reticulo)

# Crear gráfico
fig, ax = plt.subplots(figsize=(7, 6))
sc = ax.scatter(reticulo[:, 0], reticulo[:, 1], color='blue', s=20, label='Retículo', zorder=3)

# Dibujar vectores base
origen = np.array([0, 0])
ax.quiver(*origen, *v1, color='red', angles='xy', scale_units='xy', scale=1, label='v1', zorder=4)
ax.quiver(*origen, *v2, color='green', angles='xy', scale_units='xy', scale=1, label='v2', zorder=4)

# Ejes
ax.set_xlim(-6, 6)
ax.set_ylim(-6, 6)
ax.set_xticks(np.arange(-6, 7, 1))
ax.set_yticks(np.arange(-6, 7, 1))
ax.set_aspect('equal')
ax.grid(True, which='both', zorder=1)
ax.axhline(0, color='black', linewidth=0.5, zorder=2)
ax.axvline(0, color='black', linewidth=0.5, zorder=2)
ax.legend(loc='center left', bbox_to_anchor=(1, 0.5))
ax.set_title(f"Retículo generado por v1 = {v1.tolist()} y v2 = {v2.tolist()}")

# Evento de clic
marcador = None
flecha = None

def onclick(event):
    global marcador, flecha

    if not event.inaxes:
        return

    punto_usuario = np.array([event.xdata, event.ydata])

    # Calcular el punto más cercano del retículo
    distancias = np.linalg.norm(reticulo - punto_usuario, axis=1)
    idx_min = np.argmin(distancias)
    punto_mas_cercano = reticulo[idx_min]
    coords = indices[idx_min]

    print(f"Click: ({event.xdata:.2f}, {event.ydata:.2f})")
    print(f"Punto del retículo más cercano: {punto_mas_cercano} generado por ({coords[0]}, {coords[1]})")

    # Limpiar marcadores anteriores
    if marcador:
        marcador.remove()
    if flecha:
        flecha.remove()

    # Marcar punto clicado y vector más cercano
    marcador = ax.plot(*punto_mas_cercano, marker='o', color='magenta', markersize=8, zorder=5)[0]
    flecha = ax.annotate(
        '', xy=punto_mas_cercano, xytext=punto_usuario,
        arrowprops=dict(arrowstyle='->', color='magenta', lw=1.5), zorder=4
    )
    fig.canvas.draw()

# Conectar evento
fig.canvas.mpl_connect('button_press_event', onclick)

plt.tight_layout()
plt.show()
