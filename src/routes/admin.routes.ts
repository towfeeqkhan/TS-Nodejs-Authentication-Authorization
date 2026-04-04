import express, { Request, Response } from "express";
import requireAuth from "../middleware/requireAuth.middleware";
import requireRole from "../middleware/requireRole.middleware";

const router = express.Router();

router.get(
  "/all-users",
  requireAuth,
  requireRole("admin"),
  (req: Request, res: Response) => {
    return res.json({ message: "List of all users" });
  },
);

export default router;
