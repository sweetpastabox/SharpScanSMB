/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.RPC;

namespace SMBLibrary.Services
{
    /// <summary>
    /// [MS-SRVS] SHARE_INFO_0_CONTAINER
    /// </summary>
    public class ShareInfo0Container : IShareInfoContainer
    {
        public NDRConformantArray<ShareInfo0Entry>? Entries;

        public ShareInfo0Container()
        {
        }

        public ShareInfo0Container(NDRParser parser)
        {
            Read(parser);
        }

        public void Read(NDRParser parser)
        {
            parser.BeginStructure();
            _ = parser.ReadUInt32();
            parser.ReadEmbeddedStructureFullPointer(ref Entries);
            parser.EndStructure();
        }

        public void Write(NDRWriter writer)
        {
            writer.BeginStructure();
            writer.WriteUInt32((uint)Count);
            writer.WriteEmbeddedStructureFullPointer(Entries);
            writer.EndStructure();
        }

        public uint Level => 0;

        public int Count => Entries?.Count ?? 0;

        public void Add(ShareInfo0Entry entry)
        {
            Entries ??= new NDRConformantArray<ShareInfo0Entry>();
            Entries.Add(entry);
        }
    }
}
