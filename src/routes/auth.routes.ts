import express from "express";
import {
  loginHandler,
  registerHandler,
  verifyEmailHandler,
} from "../controllers/auth/auth.controller";

const router = express.Router();

router.post("/register", registerHandler);
router.get("/verify-email", verifyEmailHandler);
router.post("/login", loginHandler);

export default router;
