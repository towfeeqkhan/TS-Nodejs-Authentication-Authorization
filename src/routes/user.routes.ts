import express, { Request, Response } from "express";
import requireAuth from "../middleware/requireAuth.middleware";

const router = express.Router();

router.get("/me", requireAuth, (req: Request, res: Response) => {
  const user = (req as any).user;

  return res.status(200).json({ user: user });
});

export default router;
