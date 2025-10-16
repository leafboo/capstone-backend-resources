import mysql from 'mysql2/promise';
// 

// 1 pool can manage many user connections (5-20)
const pool = mysql.createPool({
    host: process.env.DATABASE_IP,
    user: 'root',
    password: 'password',
    database: 'capstone',
    port: 3333,
    connectionLimit: 10
})


export { pool };