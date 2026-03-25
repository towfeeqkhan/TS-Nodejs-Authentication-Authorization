import jwt from "jsonwebtoken";

export function generateToken(
  userId: string,
  role: "user" | "admin",
  tokenVersion: number,
) {
  const accessToken = jwt.sign(
    {
      _id: userId,
      role,
      tokenVersion,
    },
    process.env.JWT_ACCESS_SECRET!,
    {
      expiresIn: "30m",
    },
  );

  const refreshToken = jwt.sign(
    {
      _id: userId,
      tokenVersion,
    },
    process.env.JWT_REFRESH_SECRET!,
    {
      expiresIn: "7d",
    },
  );

  return { accessToken, refreshToken };
}
