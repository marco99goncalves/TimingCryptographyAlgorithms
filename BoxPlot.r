data <- data.frame(B2 = c(

                            52.928924560546875,

                            66.28036499023438,

                            69.85664367675781,

                            73.90975952148438,

                            88.21487426757812),

                   B2 = c(

                        46.01478576660156,

                        46.253204345703125,

                        47.44529724121094,

                        52.69050598144531,

                        75.81710815429688),

                   B4 = c(

                        47.44529724121094,

                        50.067901611328125,

                        50.54473876953125,

                        50.78315734863281,

                        53.16734313964844))
head(data) 

boxplot(data, names=c("2 Bytes", "4 Bytes", "8 Bytes"))