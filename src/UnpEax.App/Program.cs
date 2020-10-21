using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.IO.MemoryMappedFiles;
using System.Threading.Tasks;
using System.Xml;

namespace UnpEax.App
{
    /// <summary>
    /// UnpEax, for extracting (but not decrypting) EAppX/EAppXBundle/EMsiX/EMsiXBundle files
    /// </summary>
    /// See: https://gist.github.com/WalkingCat/1c119933f7f6ce0e00c45a4fb80f2686
    class Program
    {
        static async Task Main(string[] args)
        {
            // Path to file
            var path = @"";
            using var mmap = MemoryMappedFile.CreateFromFile(path, FileMode.Open);
            Extract(mmap, Path.ChangeExtension(path, null), "");
        }

        static Stream ReadData(MemoryMappedFile mmap, long offset, long count, bool unzip = false)
        {
            var strm = (count > 0) ? mmap.CreateViewStream(offset, count) as Stream : new MemoryStream(0);
            return unzip ? new DeflateStream(strm, CompressionMode.Decompress) as Stream : strm;
        }

        static void WriteFile(string dir, string path, Stream stream, bool encrypted = false)
        {
            Console.Write(" Extracting: {0}", path);
            if (encrypted)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write(" [Encrypted]");
                Console.ResetColor();
            }

            Console.WriteLine();

            var fullpath = Path.Combine(dir, path);
            Directory.CreateDirectory(Path.GetDirectoryName(fullpath));
            using var file = File.Create(fullpath);
            stream.CopyTo(file);
            stream.Dispose(); // BEWARE
        }

        class Part
        {
            public int id;
            public short zipped;
            public short flags;
            public long pos;
            public long len_orig;
            public long len;
            public string path;
            public bool isPackage;
        }

        static void Extract(MemoryMappedFile mmap, string root_dir, string dir, long offset = 0)
        {
            bool is_bundle = false;
            using var header_view_0 = mmap.CreateViewAccessor(offset, 6);

            var magic = header_view_0.ReadInt32(0);
            if (magic == 0x48425845) // EXBH
            {
                is_bundle = true;
            }
            else if ((magic    != 0x48505845)  // EXPH
                     && (magic != 0x48535845)) // EXSH ??
            {
                Console.WriteLine("\n invalid file\n");
                return;
            }

            var header_size = header_view_0.ReadUInt16(4);
            header_view_0.Dispose();

            using var header_view = mmap.CreateViewAccessor(offset, header_size);
            long pos = 6;
            Func<Int64> ReadInt64 = () =>
            {
                var ret = header_view.ReadInt64(pos);
                pos += 8;
                return ret;
            };
            Func<Int32> ReadInt32 = () =>
            {
                var ret = header_view.ReadInt32(pos);
                pos += 4;
                return ret;
            };
            Func<Int16> ReadInt16 = () =>
            {
                var ret = header_view.ReadInt16(pos);
                pos += 2;
                return ret;
            };
            Func<int, byte[]> ReadBytes = count =>
            {
                var data = new byte[count];
                header_view.ReadArray(pos, data, 0, count);
                pos += count;
                return data;
            };
            Func<int, string> ReadString = count => { return System.Text.Encoding.Unicode.GetString(ReadBytes(count)); };

            // See: https://pastebin.com/zH5tet0b
            var file_version = ReadInt64();

            var footer_offset = ReadInt64();
            var footer_length = ReadInt64();
            var file_count = ReadInt64();

            var sig_offset = ReadInt64();
            var sig_zipped = ReadInt16();
            var sig_length_orig = ReadInt32();
            var sig_length = ReadInt32();

            var coin_offset = ReadInt64();
            var coin_zipped = ReadInt16();
            var coin_length_origin = ReadInt32();
            var coin_length = ReadInt32();

            var block_map_file_ID = ReadInt64();

            var key_len = ReadInt32();
            var key_count = ReadInt16();
            var keys = new List<Guid>();
            for (int i = 0; i < key_len/16; ++i)
            {
                keys.Add(new Guid(ReadBytes(16)));
            }

            var packname_str_len = ReadInt16();
            var packname_byte_len = ReadInt16();
            var packname = ReadString(packname_byte_len);

            var crypto_algo_len = ReadInt16();
            var crypto_algo = ReadString(crypto_algo_len);

            var diffusion_support_enabled = ReadInt16();
            var block_map_hash_method_len = ReadInt16();
            var block_map_hash_method = ReadString(block_map_hash_method_len);

            var block_map_hash_len = ReadInt16();
            var block_map_hash = ReadBytes(block_map_hash_len);

            bool end = pos == header_size;

            if ((sig_offset != 0) && (sig_length) != 0)
            {
                WriteFile(root_dir, Path.Combine(dir, "AppxSignature.p7x"),
                    ReadData(mmap, sig_offset, sig_length, true)
                );
            }

            if ((coin_offset != 0) && (coin_length) != 0)
            {
                WriteFile(root_dir, Path.Combine(dir, "AppxMetadata\\CodeIntegrity.cat"),
                    ReadData(mmap, coin_offset, coin_length, true)
                );
            }

            using var parts_acc = mmap.CreateViewAccessor(
                offset + footer_offset, footer_length
            );
            var parts = new List<Part>();
            for (var i = 0; i < (parts_acc.Capacity / 40); ++i)
            {
                long p_offset = i * 40;
                parts.Add(new Part()
                          {
                              id = parts_acc.ReadInt32(p_offset       + 8),
                              flags = parts_acc.ReadInt16(p_offset    + 4),
                              zipped = parts_acc.ReadInt16(p_offset   + 6),
                              pos = parts_acc.ReadInt64(p_offset      + 16),
                              len_orig = parts_acc.ReadInt64(p_offset + 24),
                              len = parts_acc.ReadInt64(p_offset      + 32),
                              path = "part" + i.ToString() + ".dat",
                              isPackage = false,
                          });
            }

            if (parts.Count > 0)
            {
                var bmap_part = parts[parts.Count - 1]; // Sure ?
                bmap_part.path = "AppxBlockMap.xml";
                using var strm = ReadData(mmap, offset + bmap_part.pos,
                    bmap_part.len, bmap_part.zipped == 1);
                var xml = new XmlDocument();
                xml.Load(strm);
                foreach (XmlElement elem in xml.DocumentElement.ChildNodes)
                {
                    var id_str = elem.GetAttribute("Id");
                    var name = elem.GetAttribute("Name");
                    if (!(string.IsNullOrEmpty(id_str) || string.IsNullOrEmpty(name)))
                    {
                        var id = int.Parse(id_str, System.Globalization.NumberStyles.HexNumber);
                        var part = parts.Find(p => p.id == id);
                        if (part is object)
                        {
                            part.path = name;
                        }
                    }
                }
            }

            if (is_bundle)
            {
                var bman_part = parts.Find(p => p.path == "AppxMetadata\\AppxBundleManifest.xml");
                if (bman_part is object)
                {
                    using var strm = ReadData(mmap,
                        offset + bman_part.pos, bman_part.len,
                        bman_part.zipped == 1
                    );
                    var xml = new XmlDocument();
                    xml.Load(strm);
                    foreach (XmlElement elem in xml.DocumentElement.ChildNodes)
                    {
                        if (elem.Name == "Packages")
                        {
                            foreach (XmlElement elem_ in elem.ChildNodes)
                            {
                                var offset_str = elem_.GetAttribute("Offset");
                                var filename = elem_.GetAttribute("FileName");
                                if (!(string.IsNullOrEmpty(offset_str) || string.IsNullOrEmpty(filename)))
                                {
                                    var offset_ = int.Parse(offset_str);
                                    var part = parts.Find(p => p.pos == offset_);
                                    if (part is object)
                                    {
                                        part.path = filename;
                                        part.isPackage = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            foreach (var part in parts)
            {
                if (part.isPackage)
                {
                    Extract(mmap, root_dir, Path.Combine(dir, Path.ChangeExtension(part.path, null)), part.pos);
                }
                else
                {
                    WriteFile(root_dir, Path.Combine(dir, part.path),
                        ReadData(mmap, offset + part.pos, part.len, part.zipped == 1),
                        part.flags == 0);
                }
            }
        }
    }
}