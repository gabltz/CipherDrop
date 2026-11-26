declare module "virtual:docs" {
  export interface DocSection {
    id: string;
    heading: string;
    text: string;
  }
  export interface DocPage {
    slug: string;
    title: string;
    /** HTML rendered at build time from the repository's docs/*.md (trusted). */
    html: string;
    sections: DocSection[];
  }
  const pages: DocPage[];
  export default pages;
}
