const express = require('express');
const cors = require('cors');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const multer = require('multer');
const fs = require('fs');
const crypto = require('crypto');
const sharp = require('sharp'); // <--- Importado para compresión de imágenes
const readline = require('readline');
const { once } = require('events');

// Carpeta donde viven los datos (base de datos, fotos y respaldos).
// En un hosting en la nube, apúntala a un disco persistente con la variable DATA_DIR.
const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : __dirname;
fs.mkdirSync(DATA_DIR, { recursive: true });

// En Render el disco normal se BORRA en cada deploy. Solo un "Persistent Disk" conserva los datos.
if (process.env.RENDER && !process.env.DATA_DIR) {
    console.warn('\n⚠️  ATENCIÓN: estás en Render pero DATA_DIR no está definida.');
    console.warn('⚠️  La base de datos y las fotos se perderán en el próximo deploy.');
    console.warn('⚠️  Crea un Persistent Disk (Mount Path /var/data) y agrega la variable DATA_DIR=/var/data\n');
}

// Primera vez con un disco persistente vacío: copia la base y las fotos que vienen en el repositorio.
// Nunca sobrescribe nada que ya exista en el disco.
function sembrarDatosIniciales(uploadsDestino) {
    if (DATA_DIR === __dirname) return;
    try {
        const dbDestino = path.join(DATA_DIR, 'idec_peronia.db');
        const dbOrigen = path.join(__dirname, 'idec_peronia.db');
        if (!fs.existsSync(dbDestino) && fs.existsSync(dbOrigen)) {
            fs.copyFileSync(dbOrigen, dbDestino);
            console.log('Base de datos inicial copiada al disco persistente.');
        }
        const upOrigen = path.join(__dirname, 'public', 'uploads');
        if (fs.existsSync(upOrigen)) fs.cpSync(upOrigen, uploadsDestino, { recursive: true, force: false });
    } catch (e) { console.error('No se pudieron copiar los datos iniciales:', e.message); }
}

const app = express();
app.use(cors());
app.use(express.json());

const uploadDir = process.env.DATA_DIR ? path.join(DATA_DIR, 'uploads') : path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}
sembrarDatosIniciales(uploadDir);

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 100 * 1024 * 1024 } 
});

// Solo imágenes para los cuadros de contenido (con multer temporal antes de procesar con sharp)
const uploadImg = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => cb(null, uploadDir),
        filename: (req, file, cb) => cb(null, 'temp-' + Date.now() + path.extname(file.originalname))
    }),
    limits: { fileSize: 20 * 1024 * 1024 },
    fileFilter: (req, file, cb) => cb(null, file.mimetype.startsWith('image/'))
});

// Función auxiliar para procesar y comprimir imágenes con Sharp
async function procesarImagenSharp(filePath) {
    const filename = `optimized-${Date.now()}-${Math.round(Math.random() * 1E9)}.webp`;
    const outputPath = path.join(uploadDir, filename);

    await sharp(filePath)
        .resize({ width: 1200, withoutEnlargement: true }) // Ancho máximo razonable para web
        .webp({ quality: 80 }) // Calidad optimizada del 80%
        .toFile(outputPath);

    // Borrar el archivo temporal original
    if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
    }

    return `/uploads/${filename}`;
}

const LAYOUTS = ['arriba', 'abajo', 'izquierda', 'derecha'];
const TAMANOS = ['pequeno', 'mediano', 'grande', 'completo'];

function parseImgs(v) {
    try { const a = JSON.parse(v || '[]'); return Array.isArray(a) ? a : []; } catch (e) { return []; }
}
function borrarArchivoUpload(url) {
    if (typeof url !== 'string' || !url.startsWith('/uploads/')) return;
    try { const f = path.join(uploadDir, path.basename(url)); if (fs.existsSync(f)) fs.unlinkSync(f); } catch (e) {}
}


// ============================================================
//  SEGURIDAD: contraseñas con hash + sesiones por token
// ============================================================
function hashPassword(plain) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(plain, salt, 64).toString('hex');
    return `scrypt$${salt}$${hash}`;
}

function verificarPassword(plain, guardada) {
    if (guardada.startsWith('scrypt$')) {
        const [, salt, hash] = guardada.split('$');
        const calc = crypto.scryptSync(plain, salt, 64);
        const orig = Buffer.from(hash, 'hex');
        return calc.length === orig.length && crypto.timingSafeEqual(calc, orig);
    }
    const a = Buffer.from(plain);
    const b = Buffer.from(guardada);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
}

const SESION_HORAS = 12;
const sesiones = new Map();

function crearSesion(user) {
    const token = crypto.randomBytes(32).toString('hex');
    sesiones.set(token, { exp: Date.now() + SESION_HORAS * 3600 * 1000, id: user.id, usuario: user.usuario, rol: user.rol || 'admin', permisos: permisosDe(user) });
    return token;
}

function sesionValida(token) {
    const ses = sesiones.get(token);
    if (!ses) return false;
    if (ses.exp < Date.now()) { sesiones.delete(token); return false; }
    return true;
}

function tokenDe(req) { return (req.headers.authorization || '').replace(/^Bearer\s+/i, ''); }
function sesionDe(req) { const t = tokenDe(req); return sesionValida(t) ? sesiones.get(t) : null; }
function cerrarSesionesDe(idUsuario, exceptoToken) {
    for (const [t, ses] of sesiones) if (ses.id === idUsuario && t !== exceptoToken) sesiones.delete(t);
}

// ------------------------------------------------------------
//  PERMISOS (cada persona puede tener solo lo que necesita)
//   textos    -> editar títulos y textos (secciones y cuadros)
//   imagenes  -> agregar, quitar y acomodar fotos de secciones y cuadros
//   cuadros   -> crear, borrar y mover cuadros
//   secciones -> crear, borrar y mover secciones del menú
//   galeria   -> subir y borrar fotos/videos de la Galería
//   avisos    -> eventos del calendario
//   redes     -> redes sociales
//   ubicacion -> mapa y enlace de ubicación
//  El rol 'admin' puede todo (incluye usuarios, estilos, mantenimiento y respaldos).
// ------------------------------------------------------------
const PERMISOS = ['textos', 'imagenes', 'cuadros', 'secciones', 'galeria', 'avisos', 'redes', 'ubicacion'];
const ROLES_VALIDOS = ['admin', 'editor', 'galeria', 'personalizado'];
const PRESETS = {
    admin: PERMISOS.slice(),
    editor: ['textos', 'imagenes', 'cuadros', 'secciones', 'avisos', 'redes', 'ubicacion'], // igual que antes
    galeria: ['galeria'],                                                                    // igual que antes
    personalizado: []
};

function limpiarPermisos(lista) {
    return Array.isArray(lista) ? PERMISOS.filter(p => lista.includes(p)) : [];
}
// Usuarios antiguos (rol editor/galeria sin lista) siguen funcionando igual que antes
function permisosDe(user) {
    if ((user.rol || 'admin') === 'admin') return PERMISOS.slice();
    if (user.permisos) { try { return limpiarPermisos(JSON.parse(user.permisos)); } catch (e) {} }
    return (PRESETS[user.rol] || []).slice();
}
function tiene(ses, permiso) { return !!ses && (ses.rol === 'admin' || ses.permisos.includes(permiso)); }

function rutaEn(p, base) { return p === base || p.startsWith(base + '/'); }
function permitido(ses, metodo, p, body) {
    if (ses.rol === 'admin') return true;
    if (p === '/logout' || p === '/cuenta/password') return true;
    const t = k => ses.permisos.includes(k);
    if (rutaEn(p, '/galeria')) return t('galeria');
    if (rutaEn(p, '/avisos')) return t('avisos');
    if (rutaEn(p, '/redes-sociales')) return t('redes');
    if (p === '/configuracion' && metodo === 'PUT') {
        // Solo la ubicación del mapa dentro de la configuración
        const claves = Object.keys(body || {});
        return t('ubicacion') && claves.length > 0 && claves.every(k => ['mapa_direccion', 'ubicacion_url'].includes(k));
    }
    if (rutaEn(p, '/apartados')) return metodo === 'PUT' ? (t('textos') || t('imagenes')) : t('cuadros');
    if (rutaEn(p, '/contenido')) return metodo === 'PUT' ? (t('textos') || t('imagenes')) : t('secciones');
    return false; // usuarios, logo, estilos, mantenimiento, historial... solo administrador
}

// Borra las fotos temporales que multer ya guardó cuando no se van a usar
function descartarArchivos(files) {
    (files || []).forEach(f => { try { if (f && f.path && fs.existsSync(f.path)) fs.unlinkSync(f.path); } catch (e) {} });
}

// Texto legible para el historial de cambios
function describirAccion(metodo, p) {
    const partes = p.replace(/^\//, '').split('/');
    const nombres = { configuracion: 'la configuración', contenido: 'una sección', apartados: 'un cuadro', avisos: 'un aviso del calendario', 'redes-sociales': 'una red social', galeria: 'un elemento de la galería', usuarios: 'un administrador', cuenta: 'su contraseña' };
    if (partes[0] === 'respaldo') return 'Restauró un respaldo completo del sitio';
    if (partes[1] === 'logo') return 'Cambió el logo';
    if (partes[0] === 'cuenta') return 'Cambió su contraseña';
    const recurso = nombres[partes[0]] || partes[0];
    if (partes[partes.length - 1] === 'mover') return `Movió ${recurso}`;
    const verbo = { POST: 'Agregó', PUT: 'Modificó', PATCH: 'Modificó', DELETE: 'Eliminó' }[metodo] || metodo;
    const detalle = partes[0] === 'contenido' && partes[1] ? ` («${partes[1]}»)` : '';
    return `${verbo} ${recurso}${detalle}`;
}

// Fecha local (por defecto Guatemala, UTC-6; se puede cambiar con TZ_OFFSET_HORAS)
const TZ_OFFSET_HORAS = Number(process.env.TZ_OFFSET_HORAS ?? -6);
function fechaLocal(offsetDias = 0) {
    return new Date(Date.now() + TZ_OFFSET_HORAS * 3600 * 1000 + offsetDias * 86400 * 1000).toISOString().slice(0, 10);
}

const visitasPorIp = new Map();
function visitaLimitada(ip) {
    const ahora = Date.now();
    const r = visitasPorIp.get(ip);
    if (!r || ahora - r.desde > 60000) { visitasPorIp.set(ip, { n: 1, desde: ahora }); return false; }
    r.n++;
    return r.n > 30;
}
setInterval(() => { const l = Date.now() - 60000; for (const [ip, r] of visitasPorIp) if (r.desde < l) visitasPorIp.delete(ip); }, 60000);

const intentosLogin = new Map();
function loginBloqueado(ip) {
    const r = intentosLogin.get(ip);
    if (!r) return false;
    if (Date.now() - r.desde > 15 * 60 * 1000) { intentosLogin.delete(ip); return false; }
    return r.n >= 10;
}
function registrarFallo(ip) {
    const r = intentosLogin.get(ip) || { n: 0, desde: Date.now() };
    r.n++;
    intentosLogin.set(ip, r);
}


// ============================================================
//  TIEMPO REAL: Server-Sent Events (index.html se actualiza solo)
// ============================================================
const clientesSSE = new Set();

function notificarCambio(tipo = 'cambio') {
    for (const c of clientesSSE) c.write(`event: ${tipo}\ndata: ${Date.now()}\n\n`);
}

setInterval(() => { for (const c of clientesSSE) c.write(': ping\n\n'); }, 25000);

app.get('/api/eventos', (req, res) => {
    res.set({
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache, no-transform',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no'
    });
    res.flushHeaders();
    res.write('retry: 3000\n\n');
    clientesSSE.add(res);
    req.on('close', () => clientesSSE.delete(res));
});

app.use('/api', (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    if (req.method === 'GET' || req.method === 'HEAD' || req.path === '/login') return next();
    if (req.path === '/visitas' && req.method === 'POST') return next(); // público y anónimo

    const ses = sesionDe(req);
    if (!ses) return res.status(401).json({ error: 'Sesión no válida. Inicia sesión de nuevo.' });
    if (!permitido(ses, req.method, req.path, req.body)) return res.status(403).json({ error: 'No tienes permiso para hacer esto.' });
    req.sesion = ses;

    if (req.path === '/logout') return next();
    res.on('finish', () => {
        if (res.statusCode >= 400) return;
        notificarCambio();
        if (db) db.run('INSERT INTO historial (fecha, usuario, accion) VALUES (?, ?, ?)', [new Date().toISOString(), ses.usuario, describirAccion(req.method, req.path)])
            .then(() => db.run('DELETE FROM historial WHERE id <= (SELECT MAX(id) FROM historial) - 1000')).catch(() => {});
    });
    next();
});

app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(uploadDir));

let db;

async function respaldarBD() {
    try {
        const dir = path.join(DATA_DIR, 'backups');
        fs.mkdirSync(dir, { recursive: true });
        const sello = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '');
        const destino = path.join(dir, `idec_peronia_${sello}.db`);
        if (!fs.existsSync(destino)) await db.exec(`VACUUM INTO '${destino.replace(/'/g, "''")}'`);
        const viejos = fs.readdirSync(dir).filter(f => f.endsWith('.db')).sort().reverse().slice(7);
        viejos.forEach(f => fs.unlinkSync(path.join(dir, f)));
    } catch (e) { console.error('No se pudo crear el respaldo:', e.message); }
}

async function iniciarBD() {
    db = await open({
        filename: path.join(DATA_DIR, 'idec_peronia.db'),
        driver: sqlite3.Database
    });

    await db.exec(`
        CREATE TABLE IF NOT EXISTS avisos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titulo TEXT NOT NULL,
            descripcion TEXT NOT NULL,
            fecha_inicio DATE,
            fecha_fin DATE,
            hora_inicio TEXT,
            hora_fin TEXT
        );
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS galeria (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titulo TEXT NOT NULL,
            tipo TEXT NOT NULL,
            url_recurso TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS contenido (
            seccion TEXT PRIMARY KEY,
            titulo TEXT NOT NULL,
            texto TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS apartados (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            seccion TEXT NOT NULL,
            subtitulo TEXT NOT NULL,
            contenido TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS configuracion (
            clave TEXT PRIMARY KEY,
            valor TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS redes_sociales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            plataforma TEXT NOT NULL,
            nombre TEXT NOT NULL,
            url TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS visitas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fecha TEXT NOT NULL,
            tipo TEXT NOT NULL,
            seccion TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_visitas_fecha ON visitas (fecha);
        CREATE TABLE IF NOT EXISTS historial (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fecha TEXT NOT NULL,
            usuario TEXT NOT NULL,
            accion TEXT NOT NULL
        );
    `);
    try { await db.exec(`ALTER TABLE usuarios ADD COLUMN rol TEXT DEFAULT 'admin';`); } catch (e) {}
    try { await db.exec(`ALTER TABLE usuarios ADD COLUMN permisos TEXT;`); } catch (e) {}

    const totalUsuarios = await db.get('SELECT COUNT(*) AS n FROM usuarios');
    if (totalUsuarios.n === 0) {
        // Mejor define ADMIN_USER y ADMIN_PASSWORD en Render y no dejes contraseñas escritas en el código
        const usuarioDefault = process.env.ADMIN_USER || 'Andres.cj';
        const passwordDefault = process.env.ADMIN_PASSWORD || 'CASTAÑONJUAREZ_2000';
        const passwordHasheada = hashPassword(passwordDefault);
        
        await db.run('INSERT INTO usuarios (usuario, password) VALUES (?, ?)', [usuarioDefault, passwordHasheada]);
        console.log(`Usuario administrador '${usuarioDefault}' creado automáticamente.`);
    }

    const totalRedes = await db.get('SELECT COUNT(*) AS n FROM redes_sociales');
    if (totalRedes.n === 0) {
        await db.run('INSERT INTO redes_sociales (plataforma, nombre, url) VALUES (?, ?, ?)',
            ['facebook', 'Facebook Oficial', 'https://www.facebook.com/idec.rios.de.vida.peronia']);
        await db.run('INSERT INTO redes_sociales (plataforma, nombre, url) VALUES (?, ?, ?)',
            ['instagram', 'Instagram Oficial', 'https://www.instagram.com/jovenesidec2026']);
    }

    try { await db.exec(`ALTER TABLE avisos ADD COLUMN hora_inicio TEXT;`); } catch (e) {}
    try { await db.exec(`ALTER TABLE avisos ADD COLUMN hora_fin TEXT;`); } catch (e) {}
    try { await db.exec(`ALTER TABLE apartados ADD COLUMN imagenes TEXT DEFAULT '[]';`); } catch (e) {}
    try { await db.exec(`ALTER TABLE apartados ADD COLUMN layout TEXT DEFAULT 'arriba';`); } catch (e) {}
    try { await db.exec(`ALTER TABLE apartados ADD COLUMN orden INTEGER DEFAULT 0;`); } catch (e) {}
    try { await db.exec(`ALTER TABLE contenido ADD COLUMN orden INTEGER DEFAULT 0;`); } catch (e) {}
    try { await db.exec(`ALTER TABLE contenido ADD COLUMN imagenes TEXT DEFAULT '[]';`); } catch (e) {}
    try { await db.exec(`ALTER TABLE contenido ADD COLUMN layout TEXT DEFAULT 'arriba';`); } catch (e) {}
    try { await db.exec(`ALTER TABLE contenido ADD COLUMN tamano TEXT DEFAULT 'mediano';`); } catch (e) {}
    try { await db.exec(`ALTER TABLE apartados ADD COLUMN tamano TEXT DEFAULT 'mediano';`); } catch (e) {}

    const configDefault = [
        { clave: 'nombre_iglesia', valor: 'IDEC PERONIA' },
        { clave: 'subtitulo_iglesia', valor: 'Iglesia de Dios Evangelio Completo' },
        { clave: 'logo_url', valor: 'idec_logo.png' },
        { clave: 'color_primary', valor: '#0f3380' },
        { clave: 'color_accent', valor: '#ffd400' },
        { clave: 'color_red', valor: '#e8261c' },
        { clave: 'mapa_direccion', valor: 'Colonia Peronia, Ciudad de Guatemala' },
        { clave: 'ubicacion_url', valor: 'https://share.google/6JxoqN9HezwIXOvin' },
        { clave: 'versiculo_texto', valor: '«Ámense los unos a otros con amor fraternal, respetándose y honrándose mutuamente.»' },
        { clave: 'versiculo_cita', valor: 'Romanos 12:10' },
        { clave: 'pie_texto', valor: 'Llevando el mensaje de Salvación y Vida Eterna.' }
    ];

    for (const c of configDefault) {
        const existe = await db.get('SELECT * FROM configuracion WHERE clave = ?', [c.clave]);
        if (!existe) {
            await db.run('INSERT INTO configuracion (clave, valor) VALUES (?, ?)', [c.clave, c.valor]);
        }
    }

    const paletaVieja = { color_primary: '#0a192f', color_accent: '#f1c40f', color_red: '#e74c3c' };
    const paletaNueva = { color_primary: '#0f3380', color_accent: '#ffd400', color_red: '#e8261c' };
    for (const [clave, viejo] of Object.entries(paletaVieja)) {
        const fila = await db.get('SELECT valor FROM configuracion WHERE clave = ?', [clave]);
        if (fila && fila.valor.toLowerCase() === viejo) {
            await db.run('UPDATE configuracion SET valor = ? WHERE clave = ?', [paletaNueva[clave], clave]);
        }
    }

    await db.run("UPDATE configuracion SET valor = ? WHERE clave = 'nombre_iglesia' AND valor = ?", ['IDEC | Ríos de Vida | Ciudad Peronia', 'IDEC PERONIA']);

    const seccionesDefault = [
        { seccion: 'inicio', titulo: 'Bienvenidos a Casa', texto: 'Nos alegra mucho saludarte. Somos una comunidad de fe comprometida con llevar el mensaje del Evangelio Completo, brindando un espacio de amor, restauración y crecimiento espiritual para toda la familia.\n\nTe invitamos a navegar por nuestro menú superior para conocer nuestros horarios de servicios, las próximas actividades en el calendario y los momentos especiales compartidos en nuestra galería.' },
        { seccion: 'horarios', titulo: 'Horarios de Servicios', texto: 'Consulta nuestros días y horarios de reunión semanal.' },
        { seccion: 'calendario', titulo: 'Calendario de Actividades', texto: 'Mantente al tanto de nuestros próximos eventos y actividades especiales.' },
        { seccion: 'galeria', titulo: 'Galería de Momentos', texto: 'Fotografías y videos ordenados por apartados.' },
        { seccion: 'ubicacion', titulo: 'Cómo llegar', texto: 'Te esperamos con los brazos abiertos. Aquí encuentras nuestra ubicación y cómo llegar a la iglesia.' },
        { seccion: 'contacto', titulo: 'Contacto & Ubicación', texto: 'Nos encantaría estar en contacto contigo y recibir tus peticiones de oración.\n\n📍 Dirección: Colonia Peronia, Ciudad de Guatemala.\n✉️ Correo: contacto@idecperonia.org' }
    ];

    for (const item of seccionesDefault) {
        const existe = await db.get('SELECT * FROM contenido WHERE seccion = ?', [item.seccion]);
        if (!existe) {
            await db.run('INSERT INTO contenido (seccion, titulo, texto) VALUES (?, ?, ?)', [item.seccion, item.titulo, item.texto]);
        }
    }

    console.log('Base de datos SQLite lista y conectada en: ' + DATA_DIR);

    respaldarBD();
    setInterval(respaldarBD, 24 * 3600 * 1000);
}

// APIs Configuración
app.get('/api/configuracion', async (req, res) => {
    try {
        const filas = await db.all('SELECT * FROM configuracion');
        const config = {};
        filas.forEach(f => config[f.clave] = f.valor);
        res.json(config);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/configuracion', async (req, res) => {
    try {
        const confs = req.body;
        for (const [clave, valor] of Object.entries(confs)) {
            await db.run('INSERT OR REPLACE INTO configuracion (clave, valor) VALUES (?, ?)', [clave, valor]);
        }
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/configuracion/logo', upload.single('logo'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'No se subió archivo' });
        // Comprimir también el logo con sharp
        const logoUrl = await procesarImagenSharp(req.file.path);
        await db.run('INSERT OR REPLACE INTO configuracion (clave, valor) VALUES (?, ?)', ['logo_url', logoUrl]);
        res.json({ success: true, logo_url: logoUrl });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Login / Logout
app.post('/api/login', async (req, res) => {
    try {
        const ip = req.ip;
        if (loginBloqueado(ip)) return res.status(429).json({ error: 'Demasiados intentos. Espera 15 minutos.' });

        const { usuario, password } = req.body || {};
        if (!usuario || !password) return res.status(400).json({ error: 'Faltan datos' });

        const user = await db.get('SELECT * FROM usuarios WHERE usuario = ?', [String(usuario).trim()]);
        if (user && verificarPassword(String(password).trim(), user.password)) {
            if (!user.password.startsWith('scrypt$')) {
                await db.run('UPDATE usuarios SET password = ? WHERE id = ?', [hashPassword(String(password).trim()), user.id]);
            }
            intentosLogin.delete(ip);
            const token = crearSesion(user);
            res.json({ success: true, token, usuario: user.usuario, rol: user.rol || 'admin', permisos: sesiones.get(token).permisos, message: 'Bienvenido' });
        } else {
            registrarFallo(ip);
            res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// El panel pregunta aquí quién es y qué puede hacer (así los cambios de permisos se ven sin volver a entrar)
app.get('/api/cuenta', (req, res) => {
    const ses = sesionDe(req);
    if (!ses) return res.status(401).json({ error: 'Sesión no válida. Inicia sesión de nuevo.' });
    res.json({ usuario: ses.usuario, rol: ses.rol, permisos: ses.permisos });
});

app.post('/api/logout', (req, res) => {
    const token = tokenDe(req);
    sesiones.delete(token);
    res.json({ success: true });
});

// Contenido y Secciones
app.get('/api/contenido', async (req, res) => {
    try {
        const contenidos = await db.all('SELECT * FROM contenido ORDER BY orden ASC, rowid ASC');
        res.json(contenidos);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/contenido', async (req, res) => {
    try {
        const { seccion, titulo, texto } = req.body;
        const key = String(seccion).normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
        if (!key) return res.status(400).json({ error: 'Identificador no válido' });
        const mx = await db.get('SELECT COALESCE(MAX(orden), 0) AS m FROM contenido');
        await db.run('INSERT INTO contenido (seccion, titulo, texto, orden) VALUES (?, ?, ?, ?)', [key, titulo, texto, mx.m + 1]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/contenido/:seccion', (req, res) => {
    uploadImg.array('imagenes', 12)(req, res, async (err) => {
        if (err) return res.status(400).json({ error: err.message });
        try {
            const { seccion } = req.params;
            const actual = await db.get('SELECT * FROM contenido WHERE seccion = ?', [seccion]);
            if (!actual) return res.status(404).json({ error: 'Sección no encontrada' });
            const puedeTexto = tiene(req.sesion, 'textos');
            const puedeImg = tiene(req.sesion, 'imagenes');
            if (!puedeImg) descartarArchivos(req.files);
            const body = req.body;
            // Lo que la persona no tiene permitido tocar se queda exactamente como estaba
            const titulo = puedeTexto ? body.titulo : actual.titulo;
            const texto = puedeTexto ? body.texto : actual.texto;
            const layout = puedeImg ? body.layout : actual.layout;
            const tamano = puedeImg ? body.tamano : actual.tamano;
            const conservar = puedeImg ? body.conservar : undefined;

            let imgs = parseImgs(actual.imagenes);
            if (conservar !== undefined) {
                const quedan = parseImgs(conservar).filter(u => imgs.includes(u));
                imgs.filter(u => !quedan.includes(u)).forEach(borrarArchivoUpload);
                
                // Procesar cada nueva imagen subida con Sharp
                const nuevasImgs = [];
                for (const file of (req.files || [])) {
                    const optimizedUrl = await procesarImagenSharp(file.path);
                    nuevasImgs.push(optimizedUrl);
                }
                imgs = quedan.concat(nuevasImgs);
            }
            await db.run('UPDATE contenido SET titulo = ?, texto = ?, imagenes = ?, layout = ?, tamano = ? WHERE seccion = ?',
                [titulo, texto, JSON.stringify(imgs),
                 LAYOUTS.includes(layout) ? layout : (actual.layout || 'arriba'),
                 TAMANOS.includes(tamano) ? tamano : (actual.tamano || 'mediano'), seccion]);
            res.json({ success: true, message: 'Contenido actualizado correctamente' });
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });
});

app.post('/api/contenido/:seccion/mover', async (req, res) => {
    try {
        const dir = Number(req.body.dir) < 0 ? -1 : 1;
        const filas = await db.all('SELECT seccion FROM contenido ORDER BY orden ASC, rowid ASC');
        const i = filas.findIndex(f => f.seccion === req.params.seccion);
        const j = i + dir;
        if (i < 0 || j < 0 || j >= filas.length) return res.json({ success: true });
        [filas[i], filas[j]] = [filas[j], filas[i]];
        for (let k = 0; k < filas.length; k++) await db.run('UPDATE contenido SET orden = ? WHERE seccion = ?', [k + 1, filas[k].seccion]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/contenido/:seccion', async (req, res) => {
    try {
        const seccion = req.params.seccion;
        if (['inicio', 'horarios', 'calendario', 'galeria', 'contacto', 'ubicacion'].includes(seccion)) {
            return res.status(400).json({ error: 'No se pueden eliminar las secciones principales.' });
        }
        await db.run('DELETE FROM contenido WHERE seccion = ?', [seccion]);
        const propio = await db.get('SELECT imagenes FROM contenido WHERE seccion = ?', [seccion]);
        if (propio) parseImgs(propio.imagenes).forEach(borrarArchivoUpload);
        const cuadros = await db.all('SELECT imagenes FROM apartados WHERE seccion = ?', [seccion]);
        cuadros.forEach(c => parseImgs(c.imagenes).forEach(borrarArchivoUpload));
        await db.run('DELETE FROM apartados WHERE seccion = ?', [seccion]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Cuadros de contenido (texto + imágenes) dentro de cada sección
app.get('/api/apartados', async (req, res) => {
    try { res.json(await db.all('SELECT * FROM apartados ORDER BY orden ASC, id ASC')); }
    catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/apartados', (req, res) => {
    uploadImg.array('imagenes', 12)(req, res, async (err) => {
        if (err) return res.status(400).json({ error: err.message });
        try {
            const puedeTexto = tiene(req.sesion, 'textos');
            const puedeImg = tiene(req.sesion, 'imagenes');
            const { seccion, layout = 'arriba', tamano = 'mediano' } = req.body;
            const subtitulo = puedeTexto ? (req.body.subtitulo || '') : '';
            const contenido = puedeTexto ? (req.body.contenido || '') : '';
            const files = puedeImg ? (req.files || []) : [];
            if (!puedeImg) descartarArchivos(req.files);
            if (!seccion) return res.status(400).json({ error: 'Falta la sección' });
            if (!subtitulo.trim() && !contenido.trim() && !files.length) return res.status(400).json({ error: 'El cuadro está vacío' });
            
            // Procesar imágenes con Sharp
            const imgs = [];
            for (const file of files) {
                const optimizedUrl = await procesarImagenSharp(file.path);
                imgs.push(optimizedUrl);
            }

            const mx = await db.get('SELECT COALESCE(MAX(orden), 0) AS m FROM apartados WHERE seccion = ?', [seccion]);
            await db.run('INSERT INTO apartados (seccion, subtitulo, contenido, imagenes, layout, tamano, orden) VALUES (?, ?, ?, ?, ?, ?, ?)',
                [seccion, subtitulo.trim(), contenido, JSON.stringify(imgs), LAYOUTS.includes(layout) ? layout : 'arriba', TAMANOS.includes(tamano) ? tamano : 'mediano', mx.m + 1]);
            res.json({ success: true });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });
});

app.put('/api/apartados/:id', (req, res) => {
    uploadImg.array('imagenes', 12)(req, res, async (err) => {
        if (err) return res.status(400).json({ error: err.message });
        try {
            const actual = await db.get('SELECT * FROM apartados WHERE id = ?', [req.params.id]);
            if (!actual) return res.status(404).json({ error: 'Cuadro no encontrado' });
            const puedeTexto = tiene(req.sesion, 'textos');
            const puedeImg = tiene(req.sesion, 'imagenes');
            if (!puedeImg) descartarArchivos(req.files);
            // Lo que la persona no tiene permitido tocar se queda exactamente como estaba
            const subtitulo = puedeTexto ? (req.body.subtitulo || '') : actual.subtitulo;
            const contenido = puedeTexto ? (req.body.contenido || '') : actual.contenido;
            const layout = puedeImg ? (req.body.layout || 'arriba') : actual.layout;
            const tamano = puedeImg ? (req.body.tamano || 'mediano') : actual.tamano;

            let imgs = parseImgs(actual.imagenes);
            if (puedeImg) {
                const antes = imgs;
                const quedan = parseImgs(req.body.conservar || '[]').filter(u => antes.includes(u));
                antes.filter(u => !quedan.includes(u)).forEach(borrarArchivoUpload);
                const nuevasImgs = [];
                for (const file of (req.files || [])) {
                    const optimizedUrl = await procesarImagenSharp(file.path);
                    nuevasImgs.push(optimizedUrl);
                }
                imgs = quedan.concat(nuevasImgs);
            }

            if (!String(subtitulo).trim() && !String(contenido).trim() && !imgs.length) return res.status(400).json({ error: 'El cuadro está vacío' });
            await db.run('UPDATE apartados SET subtitulo = ?, contenido = ?, imagenes = ?, layout = ?, tamano = ? WHERE id = ?',
                [String(subtitulo).trim(), contenido, JSON.stringify(imgs), LAYOUTS.includes(layout) ? layout : 'arriba', TAMANOS.includes(tamano) ? tamano : 'mediano', req.params.id]);
            res.json({ success: true });
        } catch (e) { res.status(500).json({ error: e.message }); }
    });
});

app.post('/api/apartados/:id/mover', async (req, res) => {
    try {
        const dir = Number(req.body.dir) < 0 ? -1 : 1;
        const cuadro = await db.get('SELECT seccion FROM apartados WHERE id = ?', [req.params.id]);
        if (!cuadro) return res.status(404).json({ error: 'Cuadro no encontrado' });
        const filas = await db.all('SELECT id FROM apartados WHERE seccion = ? ORDER BY orden ASC, id ASC', [cuadro.seccion]);
        const i = filas.findIndex(f => String(f.id) === String(req.params.id));
        const j = i + dir;
        if (j < 0 || j >= filas.length) return res.json({ success: true });
        [filas[i], filas[j]] = [filas[j], filas[i]];
        for (let k = 0; k < filas.length; k++) await db.run('UPDATE apartados SET orden = ? WHERE id = ?', [k + 1, filas[k].id]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/apartados/:id', async (req, res) => {
    try {
        const c = await db.get('SELECT imagenes FROM apartados WHERE id = ?', [req.params.id]);
        if (c) parseImgs(c.imagenes).forEach(borrarArchivoUpload);
        await db.run('DELETE FROM apartados WHERE id = ?', [req.params.id]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Redes sociales
app.get('/api/redes-sociales', async (req, res) => {
    try { res.json(await db.all('SELECT * FROM redes_sociales ORDER BY id ASC')); }
    catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/redes-sociales', async (req, res) => {
    try {
        const { plataforma, nombre, url } = req.body || {};
        if (!plataforma || !nombre || !url) return res.status(400).json({ error: 'Faltan datos (plataforma, nombre o enlace)' });
        await db.run('INSERT INTO redes_sociales (plataforma, nombre, url) VALUES (?, ?, ?)', [plataforma, nombre, url]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/redes-sociales/:id', async (req, res) => {
    try {
        const { plataforma, nombre, url } = req.body || {};
        if (!plataforma || !nombre || !url) return res.status(400).json({ error: 'Faltan datos (plataforma, nombre o enlace)' });
        await db.run('UPDATE redes_sociales SET plataforma = ?, nombre = ?, url = ? WHERE id = ?', [plataforma, nombre, url, req.params.id]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/redes-sociales/:id', async (req, res) => {
    try {
        await db.run('DELETE FROM redes_sociales WHERE id = ?', [req.params.id]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Calendario / Avisos
app.get('/api/avisos', async (req, res) => {
    try {
        const avisos = await db.all('SELECT * FROM avisos ORDER BY fecha_inicio ASC');
        res.json(avisos);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/avisos', async (req, res) => {
    try {
        const { titulo, descripcion, fecha_inicio, fecha_fin, hora_inicio, hora_fin } = req.body;
        await db.run('INSERT INTO avisos (titulo, descripcion, fecha_inicio, fecha_fin, hora_inicio, hora_fin) VALUES (?, ?, ?, ?, ?, ?)', [titulo, descripcion, fecha_inicio, fecha_fin, hora_inicio, hora_fin]);
        res.json({ success: true, message: 'Evento guardado correctamente' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/avisos/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { titulo, descripcion, fecha_inicio, fecha_fin, hora_inicio, hora_fin } = req.body;
        await db.run('UPDATE avisos SET titulo = ?, descripcion = ?, fecha_inicio = ?, fecha_fin = ?, hora_inicio = ?, hora_fin = ? WHERE id = ?', [titulo, descripcion, fecha_inicio, fecha_fin, hora_inicio, hora_fin, id]);
        res.json({ success: true, message: 'Evento actualizado correctamente' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/avisos/:id', async (req, res) => {
    try {
        const { id } = req.params;
        await db.run('DELETE FROM avisos WHERE id = ?', [id]);
        res.json({ success: true, message: 'Evento eliminado correctamente' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Galería (Nota: Si subes videos pesados a la galería, multer los deja directos; las imágenes de galería también se pueden comprimir si gustas)
app.get('/api/galeria', async (req, res) => {
    try {
        const items = await db.all('SELECT * FROM galeria ORDER BY id DESC');
        res.json(items);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/galeria', (req, res) => {
    upload.array('archivos')(req, res, async function (err) {
        if (err) return res.status(400).json({ error: err.message });
        try {
            const { titulo } = req.body;
            if (!req.files || req.files.length === 0) return res.status(400).json({ error: 'No se subió ningún archivo' });

            for (let i = 0; i < req.files.length; i++) {
                const file = req.files[i];
                let url_recurso = `/uploads/${file.filename}`;
                let tipo = file.mimetype.startsWith('video') ? 'video' : 'imagen';

                // Si es imagen en la galería, la comprimimos con Sharp para ahorrar espacio
                if (tipo === 'imagen') {
                    try {
                        url_recurso = await procesarImagenSharp(file.path);
                    } catch (e) {
                        // Si falla la compresión, mantiene el archivo original
                    }
                }

                await db.run('INSERT INTO galeria (titulo, tipo, url_recurso) VALUES (?, ?, ?)', [titulo, tipo, url_recurso]);
            }
            res.json({ success: true, message: 'Archivos subidos correctamente' });
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });
});

app.delete('/api/galeria/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const item = await db.get('SELECT * FROM galeria WHERE id = ?', [id]);
        if (item && item.url_recurso.startsWith('/uploads/')) {
            const filePath = path.join(uploadDir, path.basename(item.url_recurso));
            if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
        }
        await db.run('DELETE FROM galeria WHERE id = ?', [id]);
        res.json({ success: true, message: 'Elemento eliminado correctamente' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
//  CUENTA, ADMINISTRADORES, VISITAS E HISTORIAL
// ============================================================
function soloAdmin(req, res) {
    const ses = sesionDe(req);
    if (!ses) { res.status(401).json({ error: 'Sesión no válida. Inicia sesión de nuevo.' }); return null; }
    if (ses.rol !== 'admin') { res.status(403).json({ error: 'Solo un administrador puede ver esto.' }); return null; }
    return ses;
}

app.post('/api/cuenta/password', async (req, res) => {
    try {
        const ses = req.sesion;
        const { actual, nueva } = req.body || {};
        if (!actual || !nueva) return res.status(400).json({ error: 'Faltan datos.' });
        if (String(nueva).length < 8) return res.status(400).json({ error: 'La nueva contraseña debe tener al menos 8 caracteres.' });
        const user = await db.get('SELECT * FROM usuarios WHERE id = ?', [ses.id]);
        if (!user || !verificarPassword(String(actual).trim(), user.password)) return res.status(403).json({ error: 'La contraseña actual no es correcta.' });
        await db.run('UPDATE usuarios SET password = ? WHERE id = ?', [hashPassword(String(nueva).trim()), user.id]);
        cerrarSesionesDe(user.id, tokenDe(req)); // cierra las demás sesiones de esta cuenta
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/usuarios', async (req, res) => {
    if (!soloAdmin(req, res)) return;
    try {
        const filas = await db.all("SELECT id, usuario, COALESCE(rol, 'admin') AS rol, permisos FROM usuarios ORDER BY id ASC");
        res.json(filas.map(u => ({ id: u.id, usuario: u.usuario, rol: u.rol, permisos: permisosDe(u) })));
    }
    catch (e) { res.status(500).json({ error: e.message }); }
});

// Rol + lista de permisos que llegan del panel -> lo que se guarda en la base
function normalizarAcceso(rol, permisos) {
    if (!ROLES_VALIDOS.includes(rol)) return { error: 'Permisos no válidos.' };
    if (rol === 'admin') return { rol: 'admin', permisos: null };
    const lista = Array.isArray(permisos) ? limpiarPermisos(permisos) : PRESETS[rol].slice();
    if (!lista.length) return { error: 'Marca al menos un permiso.' };
    return { rol: 'personalizado', permisos: JSON.stringify(lista) };
}

app.post('/api/usuarios', async (req, res) => {
    try {
        const { usuario, password, rol } = req.body || {};
        const nombre = String(usuario || '').trim();
        if (!nombre || nombre.length > 40) return res.status(400).json({ error: 'Escribe un nombre de usuario (máximo 40 caracteres).' });
        if (String(password || '').length < 8) return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres.' });
        const acceso = normalizarAcceso(rol, (req.body || {}).permisos);
        if (acceso.error) return res.status(400).json({ error: acceso.error });
        const existe = await db.get('SELECT id FROM usuarios WHERE usuario = ?', [nombre]);
        if (existe) return res.status(400).json({ error: 'Ese usuario ya existe.' });
        await db.run('INSERT INTO usuarios (usuario, password, rol, permisos) VALUES (?, ?, ?, ?)', [nombre, hashPassword(String(password).trim()), acceso.rol, acceso.permisos]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Cambiar los permisos de una persona que ya existe (se aplican de inmediato a su sesión abierta)
app.put('/api/usuarios/:id', async (req, res) => {
    try {
        const id = Number(req.params.id);
        const user = await db.get("SELECT id, COALESCE(rol, 'admin') AS rol FROM usuarios WHERE id = ?", [id]);
        if (!user) return res.status(404).json({ error: 'Usuario no encontrado.' });
        const acceso = normalizarAcceso((req.body || {}).rol, (req.body || {}).permisos);
        if (acceso.error) return res.status(400).json({ error: acceso.error });
        if (user.rol === 'admin' && acceso.rol !== 'admin') {
            if (id === req.sesion.id) return res.status(400).json({ error: 'No puedes quitarte a ti mismo el permiso de administrador.' });
            const n = await db.get("SELECT COUNT(*) AS n FROM usuarios WHERE COALESCE(rol, 'admin') = 'admin'");
            if (n.n <= 1) return res.status(400).json({ error: 'No se puede quitar al último administrador.' });
        }
        await db.run('UPDATE usuarios SET rol = ?, permisos = ? WHERE id = ?', [acceso.rol, acceso.permisos, id]);
        const nuevos = permisosDe({ rol: acceso.rol, permisos: acceso.permisos });
        for (const ses of sesiones.values()) if (ses.id === id) { ses.rol = acceso.rol; ses.permisos = nuevos; }
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/usuarios/:id', async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (id === req.sesion.id) return res.status(400).json({ error: 'No puedes quitarte el acceso a ti mismo.' });
        const user = await db.get("SELECT id, COALESCE(rol, 'admin') AS rol FROM usuarios WHERE id = ?", [id]);
        if (!user) return res.status(404).json({ error: 'Usuario no encontrado.' });
        if (user.rol === 'admin') {
            const n = await db.get("SELECT COUNT(*) AS n FROM usuarios WHERE COALESCE(rol, 'admin') = 'admin'");
            if (n.n <= 1) return res.status(400).json({ error: 'No se puede quitar al último administrador.' });
        }
        await db.run('DELETE FROM usuarios WHERE id = ?', [id]);
        cerrarSesionesDe(id);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Contador de visitas anónimo (no guarda IP ni datos personales)
app.post('/api/visitas', async (req, res) => {
    try {
        if (visitaLimitada(req.ip)) return res.status(429).json({ error: 'Demasiadas solicitudes' });
        const { tipo, seccion } = req.body || {};
        if (!['visita', 'seccion'].includes(tipo)) return res.status(400).json({ error: 'Tipo no válido' });
        const sec = typeof seccion === 'string' && /^[a-z0-9-]{1,60}$/.test(seccion) ? seccion : null;
        await db.run('INSERT INTO visitas (fecha, tipo, seccion) VALUES (?, ?, ?)', [fechaLocal(), tipo, sec]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/visitas', async (req, res) => {
    if (!soloAdmin(req, res)) return;
    try {
        const dias = Math.min(Math.max(parseInt(req.query.dias, 10) || 7, 1), 365);
        const desde = fechaLocal(-(dias - 1));
        const filas = await db.all("SELECT fecha, COUNT(*) AS n FROM visitas WHERE tipo = 'visita' AND fecha >= ? GROUP BY fecha", [desde]);
        const mapa = Object.fromEntries(filas.map(f => [f.fecha, f.n]));
        const por_dia = [];
        for (let k = dias - 1; k >= 0; k--) { const f = fechaLocal(-k); por_dia.push({ fecha: f, visitas: mapa[f] || 0 }); }
        const por_seccion = (await db.all("SELECT COALESCE(seccion, '') AS seccion, COUNT(*) AS visitas FROM visitas WHERE tipo = 'seccion' AND fecha >= ? GROUP BY seccion ORDER BY visitas DESC LIMIT 10", [desde]));
        res.json({ total: por_dia.reduce((a, d) => a + d.visitas, 0), por_dia, por_seccion });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Historial de cambios (se registra solo, en el middleware de /api)
app.get('/api/historial', async (req, res) => {
    if (!soloAdmin(req, res)) return;
    try { res.json(await db.all('SELECT fecha, usuario, accion FROM historial ORDER BY id DESC LIMIT 200')); }
    catch (e) { res.status(500).json({ error: e.message }); }
});


// ============================================================
//  RESPALDO COMPLETO (descargar / restaurar)
//  Formato .idec: una línea JSON por registro (se procesa en flujo, sin cargar todo en memoria):
//    {"t":"meta"} · {"t":"tabla","nombre":...,"filas":[...]} · {"t":"archivo","nombre":...,"data":base64} · {"t":"fin"}
//  Incluye: configuración (textos, colores, logo, mapa), secciones y su orden, cuadros y su orden,
//  posición/tamaño de las fotos, avisos, redes sociales, galería y TODOS los archivos de /uploads usados.
//  No incluye: usuarios/contraseñas, visitas ni historial (para no bloquear accesos ni mezclar estadísticas).
// ============================================================
const TABLAS_RESPALDO = ['configuracion', 'contenido', 'apartados', 'avisos', 'redes_sociales', 'galeria'];
const ORDEN_TABLA = { configuracion: 'rowid', contenido: 'orden ASC, rowid', apartados: 'orden ASC, id', avisos: 'id', redes_sociales: 'id', galeria: 'id' };
const NOMBRE_ARCHIVO_OK = /^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$/;

function archivosUsados(tablas) {
    const set = new Set();
    const re = /\/uploads\/([A-Za-z0-9][A-Za-z0-9._-]*)/g;
    for (const filas of Object.values(tablas)) {
        for (const fila of filas) {
            for (const v of Object.values(fila)) {
                if (typeof v !== 'string') continue;
                let m; re.lastIndex = 0;
                while ((m = re.exec(v))) set.add(m[1]);
            }
        }
    }
    return [...set];
}

async function escribir(res, texto) {
    if (!res.write(texto)) await once(res, 'drain');
}

app.get('/api/respaldo', async (req, res) => {
    if (!soloAdmin(req, res)) return;
    try {
        const tablas = {};
        for (const t of TABLAS_RESPALDO) tablas[t] = await db.all(`SELECT * FROM ${t} ORDER BY ${ORDEN_TABLA[t]}`);
        const usados = archivosUsados(tablas);
        const presentes = usados.filter(n => fs.existsSync(path.join(uploadDir, n)));
        const faltantes = usados.filter(n => !presentes.includes(n));

        const sello = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '');
        res.set({
            'Content-Type': 'application/octet-stream',
            'Content-Disposition': `attachment; filename="respaldo-idec-${sello}.idec"`,
            'X-Respaldo-Archivos': String(presentes.length),
            'X-Respaldo-Faltantes': String(faltantes.length),
            'Access-Control-Expose-Headers': 'X-Respaldo-Archivos, X-Respaldo-Faltantes'
        });
        await escribir(res, JSON.stringify({ t: 'meta', tipo: 'respaldo-idec', version: 2, fecha: new Date().toISOString() }) + '\n');
        for (const t of TABLAS_RESPALDO) await escribir(res, JSON.stringify({ t: 'tabla', nombre: t, filas: tablas[t] }) + '\n');
        for (const nombre of presentes) {
            await escribir(res, `{"t":"archivo","nombre":${JSON.stringify(nombre)},"data":"`);
            for await (const trozo of fs.createReadStream(path.join(uploadDir, nombre), { highWaterMark: 3 * 256 * 1024 })) {
                await escribir(res, trozo.toString('base64'));
            }
            await escribir(res, '"}\n');
        }
        res.end(JSON.stringify({ t: 'fin', archivos: presentes.length, faltantes }) + '\n');
    } catch (e) {
        console.error('Error al crear el respaldo:', e.message);
        if (!res.headersSent) res.status(500).json({ error: e.message }); else res.destroy();
    }
});

app.post('/api/respaldo', async (req, res) => {
    const tmp = path.join(DATA_DIR, 'restaurando-' + Date.now());
    const limpiar = () => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (e) {} };
    try {
        fs.mkdirSync(tmp, { recursive: true });
        const tablas = {};
        const archivos = [];
        let meta = null, fin = false;

        const rl = readline.createInterface({ input: req, crlfDelay: Infinity });
        for await (const linea of rl) {
            if (!linea.trim()) continue;
            let reg;
            try { reg = JSON.parse(linea); } catch (e) { throw new Error('El archivo está dañado o incompleto.'); }
            if (!meta) {
                if (reg.t !== 'meta' || reg.tipo !== 'respaldo-idec') throw new Error('El archivo no es un respaldo de este sitio.');
                if (reg.version !== 2) throw new Error('Versión de respaldo no compatible.');
                meta = reg;
            } else if (reg.t === 'tabla') {
                if (!TABLAS_RESPALDO.includes(reg.nombre) || !Array.isArray(reg.filas)) throw new Error('Tabla no válida en el respaldo.');
                tablas[reg.nombre] = reg.filas;
            } else if (reg.t === 'archivo') {
                if (!NOMBRE_ARCHIVO_OK.test(reg.nombre || '') || typeof reg.data !== 'string') throw new Error('Archivo no válido en el respaldo.');
                fs.writeFileSync(path.join(tmp, reg.nombre), Buffer.from(reg.data, 'base64'));
                archivos.push(reg.nombre);
            } else if (reg.t === 'fin') { fin = true; }
        }
        if (!meta) throw new Error('El archivo está vacío.');
        if (!fin) throw new Error('El respaldo está incompleto (se cortó la descarga o el archivo).');
        for (const t of TABLAS_RESPALDO) if (!Array.isArray(tablas[t])) throw new Error(`Falta la tabla «${t}» en el respaldo.`);
        if (!tablas.contenido.length || !tablas.configuracion.length) throw new Error('El respaldo no tiene contenido.');

        // Copia de seguridad del estado actual antes de tocar nada
        try {
            const dir = path.join(DATA_DIR, 'backups');
            fs.mkdirSync(dir, { recursive: true });
            const sello = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '');
            const destino = path.join(dir, `idec_peronia_${sello}_antes-de-restaurar.db`);
            if (!fs.existsSync(destino)) await db.exec(`VACUUM INTO '${destino.replace(/'/g, "''")}'`);
        } catch (e) { console.error('No se pudo guardar la copia previa a la restauración:', e.message); }

        // 1) Archivos (fotos, logo, videos) de vuelta a /uploads
        for (const nombre of archivos) {
            const origen = path.join(tmp, nombre), destino = path.join(uploadDir, nombre);
            try { fs.renameSync(origen, destino); } catch (e) { fs.copyFileSync(origen, destino); fs.unlinkSync(origen); }
        }

        // 2) Base de datos, todo o nada
        await db.exec('BEGIN');
        try {
            for (const t of TABLAS_RESPALDO) {
                const columnas = (await db.all(`PRAGMA table_info(${t})`)).map(c => c.name);
                await db.run(`DELETE FROM ${t}`);
                for (const fila of tablas[t]) {
                    const claves = Object.keys(fila).filter(k => columnas.includes(k));
                    if (!claves.length) continue;
                    await db.run(`INSERT INTO ${t} (${claves.join(', ')}) VALUES (${claves.map(() => '?').join(', ')})`, claves.map(k => fila[k]));
                }
            }
            await db.exec('COMMIT');
        } catch (e) { try { await db.exec('ROLLBACK'); } catch (x) {} throw e; }

        limpiar();
        res.json({ success: true, archivos: archivos.length });
    } catch (e) {
        limpiar();
        if (!res.headersSent) res.status(400).json({ error: e.message });
    }
});

const PORT = process.env.PORT || 3000;
iniciarBD().then(() => {
    app.listen(PORT, () => {
        console.log(`Servidor activo en http://localhost:${PORT}`);
    });
}).catch(err => {
    console.error('No se pudo iniciar la base de datos:', err);
    process.exit(1);
});
