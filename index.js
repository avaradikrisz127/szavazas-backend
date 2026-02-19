const express = require('express')
const cors = require('cors')
const cookieParser = require('cookie-parser')
const mysql = require('mysql2/promise')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const emailValidator = require('node-email-verifier');

// --- config ---
const PORT = 3000; // sulis szerver miatt majd átíródik
const HOST = 'localhost' // sulis szerver miatt majd átíródik
const JWT_SECRET = 'nagyon_nagyon_titkos_egyedi_jeszo'
const JWT_EXPIRES_IN = '7d'
const COOKIE_NAME = 'auth_token'


// --- cookie beállítás ---
const COOKIE_OPTS = {
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
    path: '/',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 nap
}

// --- adabázis beállítás ---
const db = mysql.createPool({
    host: 'localhost', // sulis szerver miatt majd átíródik
    port: '3306', // sulis szerver miatt majd átíródik
    user: 'root',
    password: '',
    database: 'szavazas'
})

// --- APP ---
const app = express();

app.use(express.json())
app.use(cookieParser())
app.use(cors({
    origin: '*',
    credentials: true
}))

function auth(req, res, next) {
    const token = req.cookies[COOKIE_NAME];
    if (!token) { // levan járva a cookie -- nem érvényes
        return res.status(409).json({ message: "nincs bejelentkezve" })
    }
    try {
        // tokenbol kinyerni a felhasznaloi adatokat
        req.user = jwt.verify(token, JWT_SECRET)
        next(); // haladhat tovabb a vegpontban
    } catch (error) {
        return res.status(410).json({ message: "nem érvényes token" })
    }
}


// --- végpontok ---

app.post('/regisztracio', async (req, res) => {
    const { email, felhasznalonev, jelszo, admin } = req.body;

    // bemeneti adatok ellenőrzése
    if (!email || !felhasznalonev || !jelszo || !admin) {
        return res.status(400).json({ message: "hiányzó bemeneti adatok" })
    }

    try {
        // valós email cím-e
        const isValid = await emailValidator(email)
        if (!isValid) {
            return res.status(401).json({ message: "nem valós emailt adtál meg" })
        }

        // ellenőrízni a felhasználónevet és emailt, hogy egyedi-e
        const emailFelhasznalonevSQL = 'SELECT * FROM felhasznalok WHERE email = ? OR felhasznalonev = ?'
        const [exists] = await db.query(emailFelhasznalonevSQL, [email, felhasznalonev]);
        if (exists.length) {
            return res.status(402).json({ message: "az email cím vagy felhasználónév már foglalt" })
        }

        // regisztráció elvégzése
        const hash = await bcrypt.hash(jelszo, 10);
        const regisztracioSQL = 'INSERT INTO felhasznalok (email, felhasznalonev, jelszo, admin) VALUES (?,?,?,?)'
        const [result] = await db.query(regisztracioSQL, [email, felhasznalonev, hash, admin])

        // válasz a felhasználónak
        return res.status(200).json({
            message: "Sikeres regisztráció",
            id: result.insertId
        })
    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: "Szerverhiba" })
    }

})

app.post('/belepes', async (req, res) => {
    const { felhasznalonevVagyEmail, jelszo } = req.body;
    // bemeneti adatok vizsgálata
    if (!felhasznalonevVagyEmail || !jelszo) {
        return res.status(400).json({ message: "hiányos belépési adatok" });
    }

    try {
        // meg kell kérdezni, hogy a megadott fiókhoz (email, felhasználónév) milyen hash jelszó tartozik
        const isValid = await emailValidator(felhasznalonevVagyEmail)
        let hashJelszo = "";
        let user = {}
        if (isValid) {
            // email + jelszót adott meg belépéskor
            const sql = 'SELECT * FROM felhasznalok WHERE email = ?'
            const [rows] = await db.query(sql, [felhasznalonevVagyEmail]);
            if (rows.length) {
                user = rows[0];
                hashJelszo = user.jelszo;
            } else {
                return res.status(401).json({ message: "Ezzel az email címmel még nem regisztráltak" })
            }
        } else {
            // felhasználónév + jelszót adott meg belépéskor
            const sql = 'SELECT * FROM felhasznalok WHERE felhasznalonev = ?'
            const [rows] = await db.query(sql, [felhasznalonevVagyEmail]);
            if (rows.length) {
                user = rows[0];
                hashJelszo = user.jelszo;
            } else {
                return res.status(402).json({ message: "Ezzel a felhasználónévvel még nem regisztráltak" })
            }
        }

        const ok = bcrypt.compare(jelszo, hashJelszo) //felhasznalónév vagy emailhez tartozó jelszó
        if (!ok) {
            return res.status(403).json({ message: "Rossz jelszót adtál meg!" })
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, felhasznalonev: user.felhasznalonev, admin: user.admin },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRES_IN }
        )

        res.cookie(COOKIE_NAME, token, COOKIE_OPTS)
        res.status(200).json({ message: "Sikeres belépés" })
    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: "szerverhiba" })
    }
})


// VÉDETT 
app.post('/kijelentkezes', auth, async (req, res) => {
    res.clearCookie(COOKIE_NAME, { path: '/' });
    res.status(200).json({ message: "sikeres kijelentkezes" })
})

// VÉDETT
app.get('/adataim', auth, async (req, res) => {
    res.status(200).json(req.user)
})

// VÉDETT
app.put('/email', auth, async (req, res) => {
    const { ujEmail } = req.body;
    if (!ujEmail) {
        return res.status(401).json({ message: "az uj email megadasa kotelezo" })
    }


    const isValid = await emailValidator(ujEmail)
    if (!isValid) {
        return res.status(403).json({ message: "az email cim formatuma nem megfelelo" })
    }
    try {
        const sql1 = 'SELECT * FROM felhasznalok WHERE email = ?'
        const [result] = await db.query(sql1, [ujEmail])
        if (result.length) {
            return res.status(403).json({ message: "az email cim mar foglalt" })
        }
        const sql2 = 'UPDATE felhasznalok SET email = ? WHERE id = ?'
        await db.query(sql2, [ujEmail, req.user.id])
        return res.status(200).json({ message: "sikeresen modosult az email" })
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: "szerverhiba" })
    }
})

app.put('/felhasznalonev', auth, async (req, res) => {
    const { ujFelhasznalonev } = req.body;
    if (!ujFelhasznalonev) {
        return res.status(401).json({ message: "az uj felhasznalonev megadasa kotelezo" })
    }

    try {
        const sql1 = 'SELECT * FROM felhasznalok WHERE felhasznalonev = ?'
        const [result] = await db.query(sql1, [ujFelhasznalonev])
        if (result.length) {
            return res.status(403).json({ message: "a felhasznalonev cim mar foglalt" })
        }
        const sql2 = 'UPDATE felhasznalok SET felhasznalonev = ? WHERE id = ?'
        await db.query(sql2, [ujFelhasznalonev, req.user.id])
        return res.status(200).json({ message: "sikeresen modosult a felhasznalonev" })
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: "szerverhiba" })
    }
})


// VÉDETT
app.put('/jelszo', async (req, res) => {
    const { jelenlegiJelszo, ujJelszo } = req.body;
    if (!jelenlegiJelszo || ujJelszo) {
        return res.status(400).json({ message: "hianyzo bemeneti adatok" })
    }
    try {

        const sql = 'SELECT * FROM felhasznalok WHERE id = ?'
        const [rows] = await db.query(sql, [req.user.id]);
        const user = rows[0];
        const hashJelszo = user.jelszo;
        // a jelenlegi jelszot osszevetjuk a hashelt jelszoval
        const ok = bcrypt.compare(jelszo, hashJelszo)
        if (!ok) {
            return res.status(401).json({message:"a regi jelszo nem helyes"})
        }

        const hashUjJelszo = await db.query(sql2, [hashUjJelszo, req.user.id])
        return res.status(200).json({message:"sikeresen modosult a jelszo"})

    } catch (error) {
        console.log(error);
        res.status(500).json({ message: "szerverhiba" })
    }
})

app.delete('/fiokom', auth, async (req, res) => {
    try {
        const sql = 'DELETE FROM felhasznalok WHERE id = ?'
        await db.query(sql, [req.user.id])

        res.clearCookie(COOKIE_NAME, { path: '/' })
        res.status(200).json({ message: "sikeres fioktorles" })
    } catch (error) {
        console.log(error)
        res.status(500).json({ message: "szerverhiba" })
    }
})


// --- szerver elindítása ---
app.listen(PORT, HOST, () => {
    console.log(`API fut: http://${HOST}:${PORT}/`);
})