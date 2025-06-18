import Button from "./ui/Button";
import Reveal from "./ui/Reveal";

const Contact = () => {
  return (
    <section className="w-full py-20 sm:py-40 justify-center flex items-center z-20" id="contact">
      <div className="flex flex-col items-center text-center">
        <Reveal>
          <h2>
            Contact <span className=" bg-gradient-to-r from-purple to-red-700 bg-clip-text text-transparent">
              me.</span>
          </h2>
        </Reveal>
        <p className="max-w-[700px] mt-10">
          {"Want more purple neon?"}
        </p>
        <p className="max-w-[700px] mt-10">
          Download my <a
            className="text-purple font-extrabold hover:scale-105 inline-block transition-transform duration-200"
            target="_blank"
            href="https://vscodethemes.com/e/atzinescandia.theplumup/theplumup/open?with=vscode"
          >
            VSCode theme
          </a> for free!
        </p>

        <a className="mt-10" href="mailto:info@atzinescandia.dev">
          <Button
            title="Let's connect"
            icon={<img src="assets/send.svg" />}
            position="right"
          />
        </a>
      </div>
    </section>
  );
};

export default Contact;
