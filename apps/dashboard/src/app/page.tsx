import { redirect } from "next/navigation";

/**
 * There is no marketing page in scope. The root lands on the overview, which is the first page
 * that says anything about what this deployment has actually analysed.
 */
export default function Home() {
  redirect("/overview");
}
