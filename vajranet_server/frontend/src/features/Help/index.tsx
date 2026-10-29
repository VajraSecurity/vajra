const Help = () => {
  return (
    <div className="h-screen w-full">
      <iframe
        src="/guide/vajra-docs-site.html"
        title="Vajra User Guide"
        className="h-full w-full border-0"
        sandbox="allow-scripts allow-same-origin"
      />
    </div>
  );
};

export default Help;

