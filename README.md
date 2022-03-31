# SDS

## Modelos

- Usuario

...

directorio Directorio


- Directorio

nombre string

carpetas map[Directorio]

ficheros map[Fichero]


- Fichero

nombre string

contenido string

** tendrá comentarios **

## Funcionamiento

Al crear un usuario:
- Se crea un directorio con nombre = /usuario.nombre

Al logearse aparece siempre en la ruta /usuario.nombre

## Comandos

- mkdir (nombreCarpeta)
- cd (nombreCarpeta o ..) 
- ls 
- touch (nombreFichero)
- cat (nombreFichero)
