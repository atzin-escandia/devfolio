"use client";

import React from "react";
import Button from "./Button";

interface DownloadCVProps {
    fileUrl: string;
    fileName: string;
}

const DownloadCV: React.FC<DownloadCVProps> = ({ fileUrl, fileName }) => {
    return (
        <Button
            title="My CV"
            icon={<img src="assets/download.svg" />
            }
            position="right"
            handleClick={() => {
                const link = document.createElement("a");
                link.href = fileUrl;
                link.download = fileName;
                link.click();
            }}
        />
    );
};

export default DownloadCV;
