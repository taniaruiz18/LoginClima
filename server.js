// Importación de dependencias
const express = require('express');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const cors = require('cors');
const mssql = require('mssql'); // Conexión con SQL Server

// Crear aplicación Express
const app = express();
const port = 3000;

// Middleware para manejar JSON y formularios
app.use(bodyParser.json());
app.use(cors()); // Si necesitas habilitar CORS para solicitudes desde otros orígenes

// Configuración de la base de datos SQL Server
// Configuración de la base de datos
const config = {
    user: '',                 // No es necesario especificar el usuario
    password: '',             // No es necesario especificar la contraseña
    server: 'localhost',      // Si SQL Server está en la misma máquina
    database: 'NEXASCORE',    // Nombre de la base de datos
    options: {
      encrypt: true,          // Cifrado (si es necesario)
      trustServerCertificate: true  // Para evitar problemas con certificados SSL no verificados
    }
  };  
// Función para mostrar un mensaje (esto se envía al cliente)
function mostrarMensaje(res, mensaje, esExito) {
    res.json({
        mensaje: mensaje,
        exito: esExito
    });
}

// Conexión a la base de datos
async function conectarBaseDatos() {
    try {
        const pool = await mssql.connect(config);
        console.log('Conectado a la base de datos');
        return pool;
    } catch (err) {
        console.error('Error al conectar a la base de datos:', err);
        throw err;
    }
}

// Ruta para registrar un estudiante
app.post('/registrarEstudiante', async (req, res) => {
    const { identificacion, nombre, correo, telefono, contrasena } = req.body;

    try {
        const pool = await conectarBaseDatos();

        // Comprobar si ya existe un estudiante con esa identificación
        const result = await pool.request()
            .input('identificacion', mssql.NVarChar, identificacion)
            .query('SELECT * FROM Sistemas_3W3 WHERE Identificacion = @identificacion');

        if (result.recordset.length > 0) {
            return mostrarMensaje(res, 'El estudiante ya está registrado', false);
        }

        // Encriptar la contraseña
        bcrypt.hash(contrasena, 10, async (err, hash) => {
            if (err) {
                return mostrarMensaje(res, 'Error al encriptar la contraseña', false);
            }

            // Guardar el estudiante en la base de datos
            await pool.request()
                .input('identificacion', mssql.NVarChar, identificacion)
                .input('nombre', mssql.NVarChar, nombre)
                .input('correo', mssql.NVarChar, correo)
                .input('telefono', mssql.NVarChar, telefono)
                .input('contrasena', mssql.NVarChar, hash)
                .query('INSERT INTO Sistemas_3W3 (Identificacion, Nombre_yapellidos, correo_electronico, Numero_Telefonico, Contraseña) VALUES (@identificacion, @nombre, @correo, @telefono, @contrasena)');

            // Enviar mensaje de éxito
            mostrarMensaje(res, 'Estudiante registrado correctamente', true);
        });
    } catch (error) {
        console.error('Error al registrar el estudiante:', error);
        mostrarMensaje(res, 'Error al registrar el estudiante', false);
    }
});

// Ruta para iniciar sesión
app.post('/iniciarSesion', async (req, res) => {
    const { identificacion, contrasena } = req.body;

    try {
        const pool = await conectarBaseDatos();

        // Buscar al estudiante por su identificación
        const result = await pool.request()
            .input('identificacion', mssql.NVarChar, identificacion)
            .query('SELECT * FROM Sistemas_3W3 WHERE Identificacion = @identificacion');

        if (result.recordset.length === 0) {
            return mostrarMensaje(res, 'Usuario no encontrado', false);
        }

        const estudiante = result.recordset[0];

        // Comparar la contraseña ingresada con la encriptada en la base de datos
        bcrypt.compare(contrasena, estudiante.Contraseña, (err, result) => {
            if (err || !result) {
                return mostrarMensaje(res, 'Contraseña incorrecta', false);
            }

            // Si la contraseña es correcta, redirigir al estudiante
            mostrarMensaje(res, `Bienvenido, ${estudiante.Nombre_yapellidos}`, true);
        });
    } catch (error) {
        console.error('Error al iniciar sesión:', error);
        mostrarMensaje(res, 'Error al iniciar sesión', false);
    }
});

// Iniciar el servidor
app.listen(port, () => {
    console.log(`Servidor corriendo en http://localhost:${port}`);
});
