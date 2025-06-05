import React from "react";
import { workExperience } from "@/data";
import { Sparkle } from "./ui/Sparkle";

const Experience = (): JSX.Element => (
  <section id="experience" className="sm:py-20 w-full">
    <h3 className="title">
      My{' '}
      <span className="bg-gradient-to-r from-purple to-red-700 bg-clip-text text-transparent">
        experience.
      </span>
    </h3>

    <div className="w-full mt-12 space-y-10">
      {workExperience.map(({ id, company, title, period, location, desc, skills }) => (
        <Sparkle key={id} duration={Math.floor(Math.random() * 10000) + 10000}>
          <div className="p-3 md:p-5 lg:p-10">
            <div className="text-start">

              <div className="flex justify-between"><div>
                <h3 className="text-justify text-lg lg:text-3xl font-extrabold">{company}</h3>
                <p className="text-xl md:text-2xl font-bold mt-3">
                  <span className="bg-gradient-to-r from-purple to-red-700 bg-clip-text text-transparent">
                    {title}
                  </span>
                </p>
              </div>

                <div className="text-end opacity-80">
                  <p>{period}</p>
                  <p>{location}</p>
                </div></div>

              <p className="my-5">{desc}</p>

              <div className="flex flex-wrap gap-2 mt-10">
                {skills.map((skill) => (
                  <div
                    key={skill}
                    className="bg-white/10 text-sm font-semibold px-4 py-2 rounded-full shadow-lg hover:bg-white/20 transition duration-200 ease-in-out"
                  >
                    {skill}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </Sparkle>
      ))}
    </div>
  </section>
);

export default Experience;
