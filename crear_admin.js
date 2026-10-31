const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const readline = require('readline');
const crypto = require('crypto');

function hashPassword(plain) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(plain, salt, 64).toString('hex');
    return `scrypt$${salt}$${hash}`;
}

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

async function gestionarUsuarios() {
    // Abrir conexión con la base de datos SQLite
    const db = await open({
        filename: require('path').join(process.env.DATA_DIR ? require('path').resolve(process.env.DATA_DIR) : __dirname, 'idec_peronia.db'),
        driver: sqlite3.Database
    });

    // Asegurar que la tabla usuarios existe
    await db.exec(`
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
    `);

    console.log('--- GESTOR DE ADMINISTRADORES IDEC PERONIA ---');
    
    rl.question('Ingresa el nombre de usuario administrador: ', (usuario) => {
        rl.question('Ingresa la contraseña: ', async (password) => {
            if (!usuario || !password) {
                console.log('❌ Error: El usuario y la contraseña no pueden estar vacíos.');
                rl.close();
                return;
            }

            try {
                const hash = hashPassword(password.trim());
                const existe = await db.get('SELECT id FROM usuarios WHERE usuario = ?', [usuario.trim()]);
                if (existe) {
                    await db.run('UPDATE usuarios SET password = ? WHERE id = ?', [hash, existe.id]);
                    console.log(`\n¡Listo! Se actualizó la contraseña del administrador '${usuario.trim()}'.`);
                } else {
                    await db.run('INSERT INTO usuarios (usuario, password) VALUES (?, ?)', [usuario.trim(), hash]);
                    console.log(`\n¡Éxito! El administrador '${usuario.trim()}' ha sido creado de forma permanente.`);
                }
            } catch (error) {
                if (error.message.includes('UNIQUE constraint failed')) {
                    console.log(`\n❌ Error: El usuario '${usuario.trim()}' ya existe en la base de datos.`);
                } else {
                    console.log(`\n❌ Error inesperado: ${error.message}`);
                }
            } finally {
                rl.close();
            }
        });
    });
}

gestionarUsuarios();