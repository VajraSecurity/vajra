/** Turns scanner-supplied HTML into plain text for PDF rendering. The output is not safe to use as HTML. */
export const stripHtmlTags = (htmlString: string): string => {
  if (!htmlString) return '';
  // Repeat, because removing one tag can join its neighbours into another: <<b>script>
  let text = htmlString;
  let previous;
  do {
    previous = text;
    text = text.replace(/<[^>]+>/g, '');
  } while (text !== previous);
  return text
    .replace(/&nbsp;/g, ' ')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/\n\s*\n/g, '\n')
    .trim();
};
