const express = require('express');
const cors = require('cors');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const multer = require('multer');
const fs = require('fs');
const crypto = require('crypto');

// Carpeta donde viven los datos (base de datos, fotos y respaldos).
// En un hosting en la nube, apúntala a un disco persistente con la variable DATA_DIR.
const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : __dirname;
fs.mkdirSync(DATA_DIR, { recursive: true });

const app = express();
app.use(cors());
app.use(express.json());

const uploadDir = process.env.DATA_DIR ? path.join(DATA_DIR, 'uploads') : path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

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

// Solo imágenes para los cuadros de contenido
const uploadImg = multer({
    storage: storage,
    limits: { fileSize: 20 * 1024 * 1024 },
    fileFilter: (req, file, cb) => cb(null, file.mimetype.startsWith('image/'))
});

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
    // Contraseña antigua en texto plano (se migra a hash en el primer login)
    const a = Buffer.from(plain);
    const b = Buffer.from(guardada);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
}

const SESION_HORAS = 12;
const sesiones = new Map(); // token -> expira (ms)

function crearSesion() {
    const token = crypto.randomBytes(32).toString('hex');
    sesiones.set(token, Date.now() + SESION_HORAS * 3600 * 1000);
    return token;
}

function sesionValida(token) {
    const exp = sesiones.get(token);
    if (!exp) return false;
    if (exp < Date.now()) { sesiones.delete(token); return false; }
    return true;
}

// Límite simple de intentos de login por IP
const intentosLogin = new Map(); // ip -> { n, desde }
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

// Todas las rutas /api: sin caché; toda escritura exige sesión y avisa a los visitantes
app.use('/api', (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    if (req.method === 'GET' || req.method === 'HEAD' || req.path === '/login') return next();

    const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    if (!sesionValida(token)) return res.status(401).json({ error: 'Sesión no válida. Inicia sesión de nuevo.' });

    if (req.path === '/logout') return next();
    res.on('finish', () => { if (res.statusCode < 400) notificarCambio(); });
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
    `);

    // Crear usuario administrador fijo por defecto si no existe ninguno
    const totalUsuarios = await db.get('SELECT COUNT(*) AS n FROM usuarios');
    if (totalUsuarios.n === 0) {
        const usuarioDefault = 'Andres.cj';
        const passwordDefault = 'CASTAÑONJUAREZ_2000';
        const passwordHasheada = hashPassword(passwordDefault);
        
        await db.run('INSERT INTO usuarios (usuario, password) VALUES (?, ?)', [usuarioDefault, passwordHasheada]);
        console.log(`Usuario administrador '${usuarioDefault}' creado automáticamente.`);
    }

    // Redes sociales iniciales (las que antes estaban fijas en index.html)
    const totalRedes = await db.get('SELECT COUNT(*) AS n FROM redes_sociales');
    if (totalRedes.n === 0) {
        await db.run('INSERT INTO redes_sociales (plataforma, nombre, url) VALUES (?, ?, ?)',
            ['facebook', 'Facebook Oficial', 'https://www.facebook.com/idec.rios.de.vida.peronia']);
        await db.run('INSERT INTO redes_sociales (plataforma, nombre, url) VALUES (?, ?, ?)',
            ['instagram', 'Instagram Oficial', 'https://www.instagram.com/jovenesidec2026']);
    }

    // Migraciones por si la base de datos ya existía
    try { await db.exec(`ALTER TABLE avisos ADD COLUMN hora_inicio TEXT;`); } catch (e) {}
    try { await db.exec(`ALTER TABLE avisos ADD COLUMN hora_fin TEXT;`); } catch (e) {}
    try { await db.exec(`ALTER TABLE apartados ADD COLUMN imagenes TEXT DEFAULT '[]';`); } catch (e) {}
    try { await db.exec(`ALTER TABLE apartados ADD COLUMN layout TEXT DEFAULT 'arriba';`); } catch (e) {}
    try { await db.exec(`ALTER TABLE apartados ADD COLUMN orden INTEGER DEFAULT 0;`); } catch (e) {}
    try { await db.exec(`ALTER TABLE contenido ADD COLUMN orden INTEGER DEFAULT 0;`); } catch (e) {}

    // Configuración por defecto
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


    // Migrar paleta antigua (azul marino/dorado) a la del logo (azul, rojo, amarillo)
    const paletaVieja = { color_primary: '#0a192f', color_accent: '#f1c40f', color_red: '#e74c3c' };
    const paletaNueva = { color_primary: '#0f3380', color_accent: '#ffd400', color_red: '#e8261c' };
    for (const [clave, viejo] of Object.entries(paletaVieja)) {
        const fila = await db.get('SELECT valor FROM configuracion WHERE clave = ?', [clave]);
        if (fila && fila.valor.toLowerCase() === viejo) {
            await db.run('UPDATE configuracion SET valor = ? WHERE clave = ?', [paletaNueva[clave], clave]);
        }
    }

    // Nombre por defecto -> logotipo en 3 líneas (solo si no lo habías personalizado)
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

    // Respaldo automático: al iniciar y cada 24 h (se conservan los últimos 7)
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
        const logoUrl = `/uploads/${req.file.filename}`;
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
            // Migrar contraseñas antiguas (texto plano) a hash
            if (!user.password.startsWith('scrypt$')) {
                await db.run('UPDATE usuarios SET password = ? WHERE id = ?', [hashPassword(String(password).trim()), user.id]);
            }
            intentosLogin.delete(ip);
            res.json({ success: true, token: crearSesion(), message: 'Bienvenido' });
        } else {
            registrarFallo(ip);
            res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/logout', (req, res) => {
    const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
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

app.put('/api/contenido/:seccion', async (req, res) => {
    try {
        const { seccion } = req.params;
        const { titulo, texto } = req.body;
        await db.run('UPDATE contenido SET titulo = ?, texto = ? WHERE seccion = ?', [titulo, texto, seccion]);
        res.json({ success: true, message: 'Contenido actualizado correctamente' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Mover una sección en el menú (dir: -1 antes, 1 después)
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

const LAYOUTS = ['arriba', 'izquierda', 'derecha'];

app.post('/api/apartados', (req, res) => {
    uploadImg.array('imagenes', 12)(req, res, async (err) => {
        if (err) return res.status(400).json({ error: err.message });
        try {
            const { seccion, subtitulo = '', contenido = '', layout = 'arriba' } = req.body;
            const files = req.files || [];
            if (!seccion) return res.status(400).json({ error: 'Falta la sección' });
            if (!subtitulo.trim() && !contenido.trim() && !files.length) return res.status(400).json({ error: 'El cuadro está vacío' });
            const imgs = files.map(f => `/uploads/${f.filename}`);
            const mx = await db.get('SELECT COALESCE(MAX(orden), 0) AS m FROM apartados WHERE seccion = ?', [seccion]);
            await db.run('INSERT INTO apartados (seccion, subtitulo, contenido, imagenes, layout, orden) VALUES (?, ?, ?, ?, ?, ?)',
                [seccion, subtitulo.trim(), contenido, JSON.stringify(imgs), LAYOUTS.includes(layout) ? layout : 'arriba', mx.m + 1]);
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
            const { subtitulo = '', contenido = '', layout = 'arriba', conservar = '[]' } = req.body;
            const antes = parseImgs(actual.imagenes);
            const quedan = parseImgs(conservar).filter(u => antes.includes(u));
            antes.filter(u => !quedan.includes(u)).forEach(borrarArchivoUpload);
            const imgs = quedan.concat((req.files || []).map(f => `/uploads/${f.filename}`));
            if (!subtitulo.trim() && !contenido.trim() && !imgs.length) return res.status(400).json({ error: 'El cuadro está vacío' });
            await db.run('UPDATE apartados SET subtitulo = ?, contenido = ?, imagenes = ?, layout = ? WHERE id = ?',
                [subtitulo.trim(), contenido, JSON.stringify(imgs), LAYOUTS.includes(layout) ? layout : 'arriba', req.params.id]);
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

// Galería
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
                const url_recurso = `/uploads/${file.filename}`;
                const tipo = file.mimetype.startsWith('video') ? 'video' : 'imagen';
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

const PORT = process.env.PORT || 3000;
iniciarBD().then(() => {
    app.listen(PORT, () => {
        console.log(`Servidor activo en http://localhost:${PORT}`);
    });
}).catch(err => {
    console.error('No se pudo iniciar la base de datos:', err);
    process.exit(1);
});