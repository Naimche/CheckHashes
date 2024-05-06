import os
import sys
import pandas as pd
import hashlib

## Script para verificar archivos con hashes MD5 y SHA256
# Hecho por: Naim C.

def calcular_hash(file_path, hash_type):
    if hash_type == 'md5':
        hash_func = hashlib.md5()
    elif hash_type == 'sha256':
        hash_func = hashlib.sha256()
    else:
        raise ValueError("Tipo de hash no válido")

    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            hash_func.update(chunk)
    return hash_func.hexdigest()


def verificar_archivos(csv_path, folder_path, output_file=None):
    # Leer el archivo CSV
    df = pd.read_csv(csv_path, header=None, names=['Archivo', 'MD5', 'SHA256', 'Ruta'])

    # Crear una lista para almacenar los resultados
    resultados = []

    # Iterar sobre cada fila del DataFrame
    for index, row in df.iterrows():
        ruta_archivo = os.path.join(folder_path, row['Ruta'])

        # Verificar si el archivo existe
        if os.path.exists(ruta_archivo):
            # Calcular los hashes del archivo actual
            md5_original = calcular_hash(ruta_archivo, 'md5')
            sha256_original = calcular_hash(ruta_archivo, 'sha256')

            # Comparar los hashes
            verificado = (row['MD5'] == md5_original) and (row['SHA256'] == sha256_original)

            # Agregar resultados a la lista
            resultados.append([row['Archivo'], row['MD5'], md5_original, row['SHA256'], sha256_original, verificado])
        else:
            # Si el archivo no se encuentra, agregamos un mensaje de error
            resultados.append(
                [row['Archivo'], row['MD5'], 'Archivo no encontrado', row['SHA256'], 'Archivo no encontrado', False])

    # Crear un DataFrame a partir de los resultados
    df_resultados = pd.DataFrame(resultados, columns=['Archivo', 'MD5 (hash proporcionado)', 'MD5 (hash original)',
                                                      'SHA256 (hash proporcionado)', 'SHA256 (hash original)',
                                                      'Verificado'])

    # Generar la tabla en formato Markdown
    markdown_table = generar_tabla_markdown(df_resultados)

    # Si se proporciona un archivo de salida, escribir la tabla en ese archivo
    if output_file:
        with open(output_file, 'w') as f:
            f.write(markdown_table)
            print(f"Tabla guardada en {output_file}")
    else:
        print(markdown_table)


def generar_tabla_markdown(df):
    # Crear encabezados de columna
    headers = "|"
    separator = "|"
    for col in df.columns:
        headers += f" {col} |"
        separator += " --- |"
    headers += "\n"
    separator += "\n"

    # Crear filas
    rows = ""
    for _, row in df.iterrows():
        row_str = "|"
        for col in df.columns:
            row_str += f" {row[col]} |"
        row_str += "\n"
        rows += row_str

    # Combinar todo
    markdown_table = headers + separator + rows
    return markdown_table


if __name__ == "__main__":
    # Obtener los argumentos de la línea de comandos
    if len(sys.argv) < 3:
        print("Uso: python main.py <pathConHashes> <pathConArchivos> [-o <nombre_archivo.md>]")
        sys.exit(1)

    csv_path = sys.argv[1]
    folder_path = sys.argv[2]

    output_file = None
    if "-o" in sys.argv:
        index = sys.argv.index("-o")
        if index + 1 < len(sys.argv):
            output_file = sys.argv[index + 1]

    # Verificar los archivos
    verificar_archivos(csv_path, folder_path, output_file)
