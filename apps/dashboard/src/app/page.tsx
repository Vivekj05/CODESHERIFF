import { redirect } from "next/navigation";

/**
 * There is no marketing page in scope. Chapter 5 puts the sign-in flow here; until then the root
 * goes straight to the repository list.
 */
export default function Home() {
  redirect("/repositories");
}
