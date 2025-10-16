import express, { type Request, type Response, type NextFunction } from "express";
import bcrypt from "bcrypt";
import { pool } from './mysqlConnection.js'
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import cors from "cors";


// remember: Every line of code is a vulnerability

const app = express();

app.use(cors({ origin: '*', credentials: true }));
app.use(express.json()); // middleware that converst JSON from request to JavaScript object
app.use(cookieParser());

app.get("/", (req, res) => {
    res.status(200);
    res.send("Welcome to the resources API");
});

// This endpoint is needed for the admin feature 
app.get("/users", (req, res) => {
    res.send("User accounts")
});


// ---------------------------------------/users-----------------------------------------------------------------------------
app.post("/users", async (req, res) => {
    const {password, userName, email} = req.body;

    if (!password) {
        return res.send("body should contain password and should not be empty");
        
    }
    
    try {
        const salt = await bcrypt.genSalt();
        const hashedPassword = await bcrypt.hash(password, salt);

        const query = 'INSERT INTO Users(UserName, Email, Salt, Hash) VALUES(?, ?, ?, ?);'
        const result = await pool.query(query, [userName, email, salt, hashedPassword]);
        res.status(201);
        res.send(result);
    } catch (err) {
        console.error(err)
        res.status(500);
    }
});

app.get("/users/me", authenticateToken, async (req, res) => {
    const userId = res.locals.user.sub;

    const query = 'SELECT * FROM Users WHERE Id = ?';
    const [ results ] = await pool.query(query, [userId]);
    const userDetails = JSON.parse(JSON.stringify(results)); // this is set to arrays by default bc of the return value of the pool.query

    res.status(200).json(userDetails[0]);
});
app.delete("/users/me", authenticateToken, async (req, res) => {
    const userId = res.locals.user.sub;

    let query = 'SELECT UserName FROM Users WHERE Id = ?';
    const [ results ] = await pool.query(query, [userId]);
    const userName = JSON.parse(JSON.stringify(results));  

    res.clearCookie('jwt_access_token', { httpOnly: true, sameSite: 'strict' });
    res.clearCookie('jwt_refresh_token', { httpOnly: true, sameSite: 'strict' });

    query = 'DELETE FROM Users WHERE Id = ?';
    await pool.query(query, [userId]);

    res.status(200).json({message: `Successfully deleted ${userName[0].UserName}`});
});

app.put("/users/me/password", authenticateToken, async (req, res) => {
    const userId = res.locals.user.sub;
    const { newPassword } = req.body;

    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(newPassword, salt);


    const query = 'UPDATE Users SET Salt = ?, Hash = ? WHERE Id = ?';
    await pool.query(query, [salt, hashedPassword, userId]);

    res.status(204).json({message: 'Password successfully updated'});
})

// ---------------------------------------/workspaces-----------------------------------------------------------------------------
app.get("/workspaces", authenticateToken, async (req, res) => {
    const userId = res.locals.user.sub;
    
    const query = 'SELECT * FROM Workspaces WHERE UserId = ?';
    const [ results ] = await pool.query(query, [userId]);
    const workspaces = JSON.parse(JSON.stringify(results));

    res.status(200).json(workspaces);
});

app.post("/workspaces", authenticateToken,  async(req, res) => {
    const userId = res.locals.user.sub;
    const {workspaceName, dateCreated} = req.body;

    const query = `INSERT INTO Workspaces (Name, DateCreated, UserId) 
                   VALUES (?, ?, ?)`;
    const [ results ] = await pool.query(query, [workspaceName, dateCreated, userId]);
    const workspaceId = JSON.parse(JSON.stringify(results)).insertId;


    res.status(201).json({message: "Workspace successfully created", workspaceId: workspaceId});

});

// ---------------------------------------/workspaces/:workspaceId-----------------------------------------------------------------------------
app.get("/workspaces/:workspaceId", authenticateToken, async (req, res) => {
    const userId = res.locals.user.sub;
    const { workspaceId } = req.params;
    
    const query = 'SELECT * FROM Workspaces WHERE Id = ? AND UserId = ?';
    const [ results ] = await pool.query(query, [workspaceId, userId]);
    const workspace = JSON.parse(JSON.stringify(results));

    res.status(200).json(workspace);
});

app.delete("/workspaces/:workspaceId", authenticateToken, async (req, res) => {
    const userId = res.locals.user.sub;
    const { workspaceId } = req.params;

    const query = 'DELETE FROM Workspaces WHERE Id = ? AND UserId = ?';
    const [ results ] = await pool.query(query, [workspaceId, userId]);
    const deleteResult = JSON.parse(JSON.stringify(results));

    res.status(200).json({message: "Workspace successfully deleted"});
});

// ---------------------------------------/researchPapers-----------------------------------------------------------------------------
app.post("/workspaces/:workspaceId/researchPapers", authenticateToken, async (req, res) => {
    const { title, authors, publicationYear, keywords, abstract, methods, findings, apa, ieee, pdfUrl} = req.body;
    const { workspaceId } = req.params;
     
    const query = `INSERT INTO ResearchPapers (Title, Authors, PublicationYear, Keywords, Abstract, Methods, Findings, APA, IEEE, PDFURL, WorkspaceId)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
    const [ results ] = await pool.query(query, [title, authors, publicationYear, keywords, abstract, methods, findings, apa, ieee, pdfUrl, workspaceId]);
    const researchPaperId = JSON.parse(JSON.stringify(results)).insertId;

    res.status(201).json({message: "Research paper successfully added", researchPaperId: researchPaperId});
});

app.get("/workspaces/:workspaceId/researchPapers", authenticateToken, async (req, res) => {
	const { workspaceId } = req.params;
	
	const query = 'SELECT * FROM ResearchPapers WHERE WorkspaceId = ?';
	const [ results ] = await pool.query(query, [workspaceId]);
	const researchPapers = JSON.parse(JSON.stringify(results));

	res.status(200).json(researchPapers)
});

app.delete("/researchPapers/:researchPaperId", authenticateToken, async (req, res) => {
	const { researchPaperId } = req.params;

	const query = 'DELETE FROM ResearchPapers WHERE Id = ?';
	await pool.query(query, [researchPaperId]);

	res.status(200).json({message: "Successfully deleted research paper"});
});


// ---------------------------------------Edit research paper cells-----------------------------------------------------------------------------
app.put("/researchPapers/:researchPaperId", authenticateToken, async (req, res) => {
    const { researchPaperId } = req.params;
    const {value, columnName} = req.body;

    const query = 'UPDATE ResearchPapers SET ' + columnName + ' = ? WHERE Id = ?';
    await pool.query(query, [value, researchPaperId]);

    res.status(200).json({message: `Successfully updated the ${columnName} attribute from the ResearchPaper table`})
});







function authenticateToken(req: Request, res: Response, next: NextFunction)  {

    const accessToken: string = req.cookies.jwt_access_token;
    

    if (accessToken === undefined || accessToken === null) {
        return res.status(403).send("No access token provided")
    }

    jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET, (err, decode) => {
        if (err) {
            if (err.name === "TokenExpiredError") {
                return res.status(401).send("Access token expired");
            }
            return res.status(403).send("Access token invalid");
        }
        res.locals.user = decode;
        next();
    });
    
}

const PORT = process.env.PORT;

app.listen(PORT, () => {
    console.log(`Server is listening in port: ${PORT}`);
});
