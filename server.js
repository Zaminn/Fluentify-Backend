
import express from "express";
import mysql from "mysql";
import cors from "cors";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import {v2 as cloudinary} from 'cloudinary';
import nodemailer from "nodemailer";

const JWT_SECRET_KEY="AAABBBAAAABBBBBCCDDDAAAD"
          
cloudinary.config({ 
  cloud_name: 'dwjltsnvn', 
  api_key: '112872344483424', 
  api_secret: 'eoAKPEe-_NatNuaIrlUy0h0Xjuo' 
});


const secretKey = JWT_SECRET_KEY;




const app = express();

app.use(bodyParser.json());
app.use(cors());
app.set('view engine','ejs');
app.use(express.urlencoded({extended:false}))

const con = mysql.createConnection({
    user: "root",
    host: "localhost",
    password: "root",
    database: "Fluentify"
})

// console.log(con);
con.connect(function(err) {
    if (err) {
      return console.error('error: ' + err.message);
    }
    else{
    console.log('Connected to the MySQL server.');
    }  
});

app.get('/forgot-password',(req,res,next)=>{
  res.render('forgot-password')
   
})
app.post('/forgot-password',(req,res,next)=>{
  const email=req.body.email;
  const newPassword=req.body.newpassword;

  const selectQuery = 'SELECT * FROM users WHERE email = ?';
  con.query(selectQuery, [email],async(selectErr, results) => {
    if (selectErr) {
      console.error(selectErr);
      return res.status(500).json({ error: 'Database Query Error' });
    }

    if(results.length === 0 ){
     return res.status(500).json({erro:"User Not Found"})
    }

     else if (results.length > 0){
      const saltRounds=10;
      const hashedNewPassword=await bcrypt.hash(newPassword,saltRounds);
      const ssql='UPDATE users SET password = ? WHERE email = ?';
      con.query(ssql,[hashedNewPassword,email],async(err,results)=>{
        if(err){
          console.log("Failed to Update");
          res.status(500).json({error:'Failed to Update'});
        }else{
          res.status(201).json({message:"Updated Successfully"})
        }
      })
    }
    


});
})

app.post('/sendEmail',(req,res,next)=>{
  const { email } = req.body;
    // res.send(email)
    // Find the user by email
    const selectQuery = 'SELECT * FROM users WHERE email = ?';
    con.query(selectQuery, [email], (selectErr, results) => {
      if (selectErr) {
        console.error(selectErr);
        return res.json({ error: 'Database Query Error' });
      }

      if (results.length === 0) {
        return res.json({ error: 'User not found' });
      }
      const user=results[0];
    

      const transporter = nodemailer.createTransport({
        service: 'gmail',
        secure: true,
        auth: {
          user: 'zaminkazmi1019@gmail.com',
          pass: 'dvwg qrge qume boyp',
        },
      });
      const mailOptions = {
        from: 'zaminkazmi1019@gmail.com',
        to: email,
        subject: 'Password Reset',
        html:'<p>Please click on the following link to verify your email address:</p>' +
        'http://localhost:3000/forgot-password' 
      };

      transporter.sendMail(mailOptions, (emailErr) => {
        if (emailErr) {
          console.error(emailErr);
          return res.status(500).json({ error: 'Failed to send reset email' });
        }

        res.json({ message: 'Reset email sent successfully' });
      });
      
    })})





app.get('/',(req,res)=>{
  res.send('hi');
})


app.listen(3000, () => {
    console.log("running backend server");
})


app.get('/welcome',(req,res)=>{
  res.send({succes:true,message:'Welcome to Backend'});
})


const verifyToken = (req, res, next) => {
  const token = req.headers.authorization;  

  if (!token) {
    return res.status(403).json({ error: 'Unauthorized - Token not provided' });
  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token' });
    }

    req.user = decoded;
    next();
  });
};

app.get('/protected-resource', verifyToken, (req, res) => {
  res.status(200).json({ message: 'This is a protected resource', user: req.user ,email:req.email});
});



app.post('/register',async (req, res) => {
  const { email,username, password } = req.body;

  const public_id="person_img_ugc4gh";
  const public_url="https://res.cloudinary.com/dwjltsnvn/image/upload/v1703168446/person_img_ugc4gh.jpg"
  const bdate="18";

 

    // Check if user with the provided email already exists
    const selectQuery = 'SELECT * FROM users WHERE email = ?';
    con.query(selectQuery, [email],async (selectErr, results) => {
      if (selectErr) {
        console.error(selectErr);
        return res.status(500).json({ error: 'Database Query Error' });
      }

      if (results.length > 0) {
       
        return res.json({ error: 'User already exists' });
      }
  
      const saltRounds=10;
        // Hash the password before storing it
      const hashedPassword = await bcrypt.hash(password,saltRounds);
      // If user doesn't exist, register the new user
      const insertQuery = 'INSERT INTO users (email, username, password) VALUES (?, ?, ?)';

      con.query(insertQuery, [email,username,hashedPassword], (insertErr) => {

        if (insertErr) {
          console.error(insertErr);
          return res.status(500).json({ error: 'Database Insert Error' });
        }

      

        const sql="SELECT id FROM users WHERE username = ?"
        con.query(sql,[username],(err,results)=>{
         if(err){
          return res.status(500).json({error:"User not Found"})
      }
         if (results.length === 0) {
          return res.status(404).json({ error: 'User not found' });
      }
       
        console.log(results);
        console.log(results[0].id)
        
        const user_id=results[0].id;
        console.log(user_id);
  
        const ssql="INSERT INTO user_data (user_id,user_name,bdate,public_id,public_url) VALUES( ?, ?, ?, ?, ?)";
          con.query(ssql,[user_id,username,bdate,public_id,public_url],(err)=>{
            if (err) {
              console.error('Error inserting data:', err);
              return res.status(500).json({ error: 'Internal Server Error' });
            }
      
            res.status(201).json({ success: true });
          }) 
   
    })
        


      });
    });
  });




app.post('/login', async (req, res) => {
  try {
    const username = req.body.username;
    const password = req.body.password;

    const sql = 'SELECT * FROM users WHERE username = ?';
    con.query(sql, [username], async (err, results) => {
      if (err) {
        console.error('Login failed:', err);
        res.status(500).json({ error: 'Login failed' });
      } else if (results.length > 0) {
        const user = results[0];

        const match = await bcrypt.compare(password, user.password);

        if (match) {
          // Issue a JWT upon successful login
          const token = jwt.sign({ username: user.username }, secretKey, { expiresIn: '1h' });
          res.status(200).json({ message: 'Login successful', token });
        } else {
          res.json({ error: 'Invalid password' });
        }
      } else {
        res.status(404).json({ error: 'User not found' });
      }
    });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});  








app.post('/PostUser',async(req,res)=>{
    const {username,bdate,public_id,public_url}=req.body;

    const sql="SELECT id FROM users WHERE username = ?"
    con.query(sql,[username],(err,results)=>{
      if(err){
      return res.status(500).json({error:"User not Found"})
      }
      if (results.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }
       
        console.log(results);
        console.log(results[0].id)
        
        const user_id=results[0].id;
        console.log(user_id);
  
        const ssql="INSERT INTO user_data (user_id,user_name,bdate,public_id,public_url) VALUES( ?, ?, ?, ?, ?)";
          con.query(ssql,[user_id,username,bdate,public_id,public_url],(err)=>{
            if (err) {
              console.error('Error inserting data:', err);
              return res.status(500).json({ error: 'Internal Server Error' });
            }
      
            res.status(201).json({ success: true });
          }) 
   
    })
})


app.post('/UpdateUser',async(req,res)=>{
  const{username,bdate,public_id,public_url}=req.body;

  const sql='UPDATE user_data SET bdate= ? , public_id=? , public_url=? WHERE user_name= ?'
  con.query(sql,[bdate,public_id,public_url,username],(err,results)=>{
    if(err){
      return res.status(500).json({error:"No Success"})
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
      let success=true
      res.send({bdate,username,public_id,public_url,success})
    
  })
})

app.post('/getUsers',async(req,res)=>{
  const username=req.body.user_name;

  const sql='SELECT * FROM users WHERE username=?';
  con.query(sql,[username],async(err,results)=>{
    if(err){
      res.status(500).json({error:"No Success"})
    }
    if(results){
      
      res.send(results)
      console.log(results);
    }
  })
})


app.post('/getUserData',async(req,res)=>{
  const user_name=req.body.userProfile;

  const sql='SELECT * FROM user_data WHERE user_name=?';
  con.query(sql,[user_name],async(err,results)=>{
    if(err){
      res.status(500).json({error:"No Success"})
    }
    if(results){
      
      res.send(results)
      console.log(results);
    }
  })
})

