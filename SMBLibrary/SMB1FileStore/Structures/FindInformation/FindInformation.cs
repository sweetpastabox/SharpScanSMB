/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.SMB1
{
    public abstract class FindInformation
    {
        public uint NextEntryOffset;

        public FindInformation()
        {
        }

        public abstract void WriteBytes(byte[] buffer, ref int offset, bool isUnicode);

        public abstract int GetLength(bool isUnicode);

        public abstract FindInformationLevel InformationLevel
        {
            get;
        }

        public static FindInformation ReadEntry(byte[] buffer, int offset, FindInformationLevel informationLevel, bool isUnicode)
        {
            return informationLevel switch
            {
                FindInformationLevel.SMB_FIND_FILE_DIRECTORY_INFO => new FindFileDirectoryInfo(buffer, offset,
                    isUnicode),
                FindInformationLevel.SMB_FIND_FILE_FULL_DIRECTORY_INFO => new FindFileFullDirectoryInfo(buffer, offset,
                    isUnicode),
                FindInformationLevel.SMB_FIND_FILE_NAMES_INFO => new FindFileNamesInfo(buffer, offset, isUnicode),
                FindInformationLevel.SMB_FIND_FILE_BOTH_DIRECTORY_INFO => new FindFileBothDirectoryInfo(buffer, offset,
                    isUnicode),
                FindInformationLevel.SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO => new FindFileIDFullDirectoryInfo(buffer,
                    offset, isUnicode),
                FindInformationLevel.SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO => new FindFileIDBothDirectoryInfo(buffer,
                    offset, isUnicode),
                _ => throw new UnsupportedInformationLevelException()
            };
        }
    }
}