import { skills } from "@/data";
import { cn } from "@/lib/utils";

interface BentoGridProps {
  className?: string;
  children?: React.ReactNode;
}

export const BentoGrid: React.FC<BentoGridProps> = ({ className, children }) => (
  <div
    className={cn(
      "grid grid-cols-1 md:grid-cols-6 lg:grid-cols-5 md:grid-row-7 gap-4 lg:gap-8 mx-auto",
      className
    )}
  >
    {children}
  </div>
);

interface BentoGridItemProps {
  className?: string;
  id: number;
  title?: string | React.ReactNode;
  description?: string | React.ReactNode;
  link?: string;
  github?: string;
  img?: string;
  titleClassName?: string;
}


export const BentoGridItem: React.FC<BentoGridItemProps> = ({
  className,
  id,
  title,
  description,
  link,
  github,
  img,
  titleClassName,
}) => (
  <div
    className={cn(
      "row-span-1 relative overflow-hidden rounded-3xl border border-white/10 group/bento hover:shadow-xl transition duration-200 flex flex-col space-y-4",
      className
    )}
  >
    <div className={cn(id === 6 && "flex justify-center", "h-full")}>
      {img && (
        <div className="w-full h-full absolute">
          <img
            src={img}
            alt={`Image for ${title}`}
            className="object-cover object-center opacity-20 w-full h-full"
          />
        </div>
      )}

      <div className={cn(id === 5 && "w-full opacity-80", "absolute right-0 -bottom-5")} />

      <div
        className={cn(
          titleClassName,
          "group-hover/bento:translate-x-2 transition duration-200 relative md:h-full min-h-40 flex flex-col px-5 py-5 lg:py-10"
        )}
      >
        <div className="flex items-end gap-5">
          <div className="space-y-10">
            {github && (
              <a
                href={github}
                target="_blank"
                rel="noopener noreferrer"
                className="cursor-pointer"
              >
                <img
                  src="assets/git.svg"
                  alt="GitHub"
                  className="min-w-8 transform transition-all duration-300 ease-in-out hover:scale-110 hover:fill-red-600 mb-2"
                />
              </a>
            )}

            {link && (
              <a
                href={link}
                target="_blank"
                rel="noopener noreferrer"
                className="cursor-pointer"
              >
                <img
                  src="assets/link.svg"
                  alt="External link"
                  className="min-w-8 transform transition-all duration-300 ease-in-out hover:scale-110 hover:fill-red-600 mb-2"
                />
              </a>
            )}
          </div>

          <div className="space-y-6">
            <p className="text-lg lg:text-3xl max-w-96 font-bold z-10">{title}</p>
            <p className="font-extralight md:max-w-[80%] md:text-xs lg:text-base text-sm z-10 opacity-70">
              {description}
            </p>

            <div className="flex flex-wrap gap-2 py-1">
              {skills.map((skill) => (
                <div
                  key={skill}
                  className="bg-white/10 text-white text-sm font-semibold px-4 py-2 rounded-full shadow-lg hover:bg-white/20 transition duration-200 ease-in-out"
                >
                  {skill}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
);
