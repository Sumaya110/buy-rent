import prisma from "../DB/db.config.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";



export const createUser = async (req, res) => {
  const { name, email, password, address, phoneNumber } = req.body;

  // Check if user already exists
  const findUser = await prisma.user.findUnique({
    where: { email: email },
  });

  if (findUser) {
    return res.status(400).json({ message: "Email already taken. Please try another email." });
  }

  // Hash password before saving
  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = await prisma.user.create({
    data: {
      name,
      email,
      password: hashedPassword,
      address,
      phoneNumber
    },
  });

  return res.json({ status: 200, data: newUser, msg: "User created" });
};


export const loginUser = async (req, res) => {
    const { email, password } = req.body;
  
    // Check if user exists
    const user = await prisma.user.findUnique({
      where: { email },
    });
  
    if (!user) {
      return res.status(400).json({ message: "Invalid email or password" });
    }
  
    // Compare entered password with stored hash
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: "Invalid email or password" });
    }
  
    // Generate JWT token
    const token = jwt.sign({ userId: user.id, email: user.email }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });
  
    return res.status(200).json({ message: "Login successful", token });
  };