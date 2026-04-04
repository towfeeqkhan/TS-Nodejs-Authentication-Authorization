import { Request, Response, NextFunction } from "express";

function requireRole(role: "user" | "admin") {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = (req as any).user;

    if (!user) {
      return res.status(401).json({
        message: "Unauthorized: User information not found. Are you logged in?",
      });
    }

    if (user.role !== role) {
      return res.status(403).json({
        message:
          "Forbidden: You do not have the required permissions to access this resource.",
      });
    }

    next();
  };
}

export default requireRole;
